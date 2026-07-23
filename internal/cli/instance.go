package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"proxpass/internal/models"
	"proxpass/internal/proxmox"

	ucli "github.com/urfave/cli/v3"
	gossh "golang.org/x/crypto/ssh"
)

func instanceCmd(deps *Deps) *ucli.Command { //nolint:gocognit,funlen,gocyclo // CLI command tree
	return &ucli.Command{
		Name:   "instance",
		Usage:  "Manage Proxmox instances",
		Action: unknownSubcmdAction,
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List Proxmox instances",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					instances, err := deps.Repo.ListProxmoxInstances(ctx)
					if err != nil {
						return err
					}
					if cmd.String(flagFormat) == formatJSON {
						return json.NewEncoder(deps.Out).Encode(instances)
					}
					if len(instances) == 0 {
						fmt.Fprintln(deps.Out, "No instances configured.")
						return nil
					}
					for _, inst := range instances {
						if inst.ConnectionType == models.ConnectionTypeSSH {
							fmt.Fprintf(deps.Out, "%-20s  API: %s  SSH: %s:%d  node: %s\n",
								inst.Name, inst.APIURL, inst.SSHHost, inst.SSHPort, inst.Node)
						} else {
							fmt.Fprintf(deps.Out, "%-20s  API: %s  node: %s  (termproxy)\n",
								inst.Name, inst.APIURL, inst.Node)
						}
					}
					return nil
				},
			},
			{
				Name:  cmdAdd,
				Usage: "Add one or more Proxmox instances",
				Description: `Adds one or more Proxmox instances to proxpass.

When a single --url is supplied, --name may optionally override the
automatically resolved node name.  When multiple --url flags are
specified, --name is disallowed and each instance is named after
its Proxmox node name.`,
				Flags: []ucli.Flag{
					&ucli.StringFlag{
						Name:  flagName,
						Usage: "Instance name (only valid with a single --url; if omitted the Proxmox node name is used)",
					},
					&ucli.StringSliceFlag{
						Name:     "url",
						Required: true,
						Usage:    "Proxmox API URL — may be repeated to add multiple instances at once (e.g. https://pve:8006)",
					},
					&ucli.StringFlag{Name: "token-id", Required: true, Usage: "API token ID (e.g. user@pam!token)"},
					&ucli.StringFlag{Name: "token-secret", Required: true, Usage: "API token secret"},
					&ucli.StringFlag{
						Name:  "connection-type",
						Value: string(models.ConnectionTypeTermProxy),
						Usage: `Connection type: "termproxy" (default) or "ssh"; applies to all supplied --url values`,
					},
					&ucli.StringFlag{
						Name: "ssh-host",
						Usage: "SSH host (host or host:port); required for --connection-type ssh with a single --url." +
							" When multiple --url are given the SSH host is derived from the node name resolved for each URL",
					},
					&ucli.StringFlag{Name: "ssh-user", Value: "root", Usage: "SSH username"},
					&ucli.StringFlag{
						Name:  "ssh-key-path",
						Usage: "Path to SSH private key (--connection-type ssh only; exclusive with --ssh-key, --generate-ssh-key)",
					},
					&ucli.StringFlag{
						Name:  "ssh-key",
						Usage: "PEM-encoded private key (--connection-type ssh only; exclusive with --ssh-key-path, --generate-ssh-key)",
					},
					&ucli.BoolFlag{
						Name:  "generate-ssh-key",
						Usage: "Generate ED25519 key pair (--connection-type ssh only)",
					},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error { //nolint:cyclop // CLI command validation is inherently branchy
					urls := cmd.StringSlice("url")

					// Disallow --name when multiple --url flags were supplied.
					if len(urls) > 1 && cmd.String(flagName) != "" {
						return fmt.Errorf(
							"--name cannot be used when multiple --url flags are specified;" +
								" each instance will be named after its Proxmox node name",
						)
					}

					connType := models.ConnectionType(cmd.String("connection-type"))
					if connType != models.ConnectionTypeTermProxy && connType != models.ConnectionTypeSSH {
						return fmt.Errorf("--connection-type must be %q or %q", models.ConnectionTypeTermProxy, models.ConnectionTypeSSH)
					}

					generateKey := cmd.Bool("generate-ssh-key")
					keyPath := cmd.String("ssh-key-path")
					keyInline := cmd.String("ssh-key")

					//nolint:nestif // SSH key validation is inherently nested
					if connType == models.ConnectionTypeSSH {
						// When multiple --url values are given, --ssh-host is not
						// required; the node name resolved from the API is used as
						// the SSH host instead.
						if len(urls) == 1 && cmd.String("ssh-host") == "" {
							return fmt.Errorf("--ssh-host is required when --connection-type ssh and a single --url is specified")
						}
						set := 0
						if keyPath != "" {
							set++
						}
						if keyInline != "" {
							set++
						}
						if generateKey {
							set++
						}
						if set == 0 {
							return fmt.Errorf("one of --ssh-key-path, --ssh-key, or --generate-ssh-key is required when --connection-type ssh")
						}
						if set > 1 {
							return fmt.Errorf("--ssh-key-path, --ssh-key, and --generate-ssh-key are mutually exclusive")
						}
					}

					// Validate all supplied URLs up-front before touching anything.
					for _, rawURL := range urls {
						if err := validateAPIURL(rawURL); err != nil {
							return err
						}
					}

					var sshKeyPEM string
					var pubKeyAuthorized string
					if connType == models.ConnectionTypeSSH {
						switch {
						case keyInline != "":
							// Validate that the supplied value is a parseable private key.
							if _, err := gossh.ParsePrivateKey([]byte(keyInline)); err != nil {
								return fmt.Errorf("--ssh-key: not a valid PEM private key: %w", err)
							}
							sshKeyPEM = keyInline
						case generateKey:
							pub, priv, err := ed25519.GenerateKey(rand.Reader)
							if err != nil {
								return fmt.Errorf("generating SSH key: %w", err)
							}
							privPEM, err := gossh.MarshalPrivateKey(priv, "")
							if err != nil {
								return fmt.Errorf("marshaling SSH private key: %w", err)
							}
							sshKeyPEM = string(pem.EncodeToMemory(privPEM))
							pubSSH, err := gossh.NewPublicKey(pub)
							if err != nil {
								return fmt.Errorf("marshaling SSH public key: %w", err)
							}
							pubKeyAuthorized = string(gossh.MarshalAuthorizedKey(pubSSH))
						}
					}

					// Add each instance in sequence.
					for _, rawURL := range urls {
						if err := addSingleInstance(ctx, deps, cmd, connType, rawURL, sshKeyPEM, pubKeyAuthorized, keyPath); err != nil {
							return err
						}
					}
					return nil
				},
			},
			{
				Name:  cmdRm,
				Usage: "Remove a Proxmox instance",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagName, Required: true, Usage: "Instance name"},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					name := cmd.String("name")
					instances, err := deps.Repo.ListProxmoxInstances(ctx)
					if err != nil {
						return err
					}
					for _, inst := range instances {
						if inst.Name == name {
							if err := deps.Repo.RemoveProxmoxInstance(ctx, inst.ID); err != nil {
								return err
							}
							fmt.Fprintf(deps.Out, "Instance %q removed.\n", name)
							return nil
						}
					}
					return fmt.Errorf("instance %q not found", name)
				},
			},
			{
				Name:      cmdInspect,
				Usage:     "Show details for one or more instances",
				ArgsUsage: argsNames,
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					if cmd.NArg() == 0 {
						return fmt.Errorf("usage: instance inspect <name> [<name> ...]")
					}
					instances, err := deps.Repo.ListProxmoxInstances(ctx)
					if err != nil {
						return err
					}
					byName := make(map[string]*models.ProxmoxInstance, len(instances))
					for _, inst := range instances {
						byName[inst.Name] = inst
					}
					var found []*models.ProxmoxInstance
					for _, name := range cmd.Args().Slice() {
						inst, ok := byName[name]
						if !ok {
							return fmt.Errorf("instance %q not found", name)
						}
						found = append(found, inst)
					}
					if cmd.String(flagFormat) == formatJSON {
						return json.NewEncoder(deps.Out).Encode(found)
					}
					for i, inst := range found {
						if i > 0 {
							fmt.Fprintln(deps.Out)
						}
						fmt.Fprintf(deps.Out, "Name:             %s\n", inst.Name)
						fmt.Fprintf(deps.Out, "API URL:          %s\n", inst.APIURL)
						fmt.Fprintf(deps.Out, "API Token ID:     %s\n", inst.APITokenID)
						fmt.Fprintf(deps.Out, "API Token Secret: %s\n", inst.APITokenSecret)
						fmt.Fprintf(deps.Out, "Connection Type:  %s\n", inst.ConnectionType)
						fmt.Fprintf(deps.Out, "Node:             %s\n", inst.Node)
						if inst.ConnectionType == models.ConnectionTypeSSH {
							fmt.Fprintf(deps.Out, "SSH Host:         %s\n", inst.SSHHost)
							fmt.Fprintf(deps.Out, "SSH Port:         %d\n", inst.SSHPort)
							fmt.Fprintf(deps.Out, "SSH User:         %s\n", inst.SSHUser)
							if inst.SSHKey != "" {
								fmt.Fprintf(deps.Out, "SSH Key:          (generated, stored in DB)\n")
							} else {
								fmt.Fprintf(deps.Out, "SSH Key Path:     %s\n", inst.SSHKeyPath)
							}
						}
					}
					return nil
				},
			},
		},
	}
}

// addSingleInstance handles adding one Proxmox instance for the given rawURL.
// It is called once per --url value from the "instance add" action.
func addSingleInstance( //nolint:cyclop // multi-URL dispatch adds branching
	ctx context.Context,
	deps *Deps,
	cmd *ucli.Command,
	connType models.ConnectionType,
	rawURL string,
	sshKeyPEM string,
	pubKeyAuthorized string,
	keyPath string,
) error {
	urls := cmd.StringSlice("url")
	multiURL := len(urls) > 1

	// When multiple --url are specified and --connection-type is ssh,
	// we derive the SSH host from the node name (see below).
	// For a single --url we respect the explicit --ssh-host value.
	explicitSSHHost := cmd.String("ssh-host")
	if multiURL {
		explicitSSHHost = "" // resolved from node name
	}

	var sshHost string
	var sshPort int
	if explicitSSHHost != "" {
		var err error
		sshHost, sshPort, err = parseHostPort(explicitSSHHost, 22)
		if err != nil {
			return fmt.Errorf("invalid --ssh-host: %w", err)
		}
	}

	// Resolve the node name from the API.
	// This validates that the API URL is reachable and determines
	// which Proxmox node name corresponds to this instance.
	nodeName, err := resolveInstanceNode(ctx, rawURL, cmd.String("token-id"), cmd.String("token-secret"), sshHost)
	if err != nil {
		return fmt.Errorf("resolving node name for %s: %w", rawURL, err)
	}

	// When multiple --url are used with --connection-type ssh,
	// use the resolved node name as the SSH host.
	if multiURL && connType == models.ConnectionTypeSSH {
		sshHost = nodeName
		sshPort = 22
	}

	// For termproxy, verify the Proxmox version supports API token auth.
	// This check runs once at instance-add time so the user gets a clear
	// error immediately rather than at connection time.
	if connType == models.ConnectionTypeTermProxy {
		if err := checkTermProxyVersion(ctx, rawURL, cmd.String("token-id"), cmd.String("token-secret")); err != nil {
			return err
		}
	}

	instName := cmd.String(flagName)
	if instName == "" {
		// Name was not supplied (or multiple URLs): fall back to the resolved node name.
		instName = nodeName
	}

	inst := &models.ProxmoxInstance{
		Name:           instName,
		APIURL:         rawURL,
		APITokenID:     cmd.String("token-id"),
		APITokenSecret: cmd.String("token-secret"),
		ConnectionType: connType,
		Node:           nodeName,
		SSHHost:        sshHost,
		SSHPort:        sshPort,
		SSHUser:        cmd.String("ssh-user"),
		SSHKeyPath:     keyPath,
		SSHKey:         sshKeyPEM,
	}
	if err := deps.Repo.AddProxmoxInstance(ctx, inst); err != nil {
		return err
	}
	fmt.Fprintf(deps.Out, "Instance %q added (connection: %s, node: %s).\n", inst.Name, inst.ConnectionType, inst.Node)
	if pubKeyAuthorized != "" {
		fmt.Fprintf(deps.Out, "Public key (add to Proxmox authorized_keys on %s):\n%s", inst.SSHHost, pubKeyAuthorized)
	}

	// Run discovery on the new instance.
	if deps.Discoverer != nil {
		// Re-read to get the DB-assigned ID.
		allInstances, err := deps.Repo.ListProxmoxInstances(ctx)
		if err != nil {
			return nil // non-fatal
		}
		for _, i := range allInstances {
			if i.Name != inst.Name {
				continue
			}
			d := deps.Discoverer(i)
			guests, err := d.DiscoverGuests(ctx)
			if err != nil {
				fmt.Fprintf(deps.ErrOut, "Discovery failed: %v\n", err)
				return nil
			}
			for _, g := range guests {
				g.InstanceID = i.ID
				_ = deps.Repo.UpsertGuest(ctx, g)
			}
			fmt.Fprintf(deps.Out, "Discovered %d guests.\n", len(guests))
			break
		}
	}
	return nil
}

// checkTermProxyVersion creates a temporary APIClient and verifies that the
// Proxmox VE version supports termproxy with API token auth.
func checkTermProxyVersion(ctx context.Context, apiURL, tokenID, tokenSecret string) error {
	inst := &models.ProxmoxInstance{
		APIURL:         apiURL,
		APITokenID:     tokenID,
		APITokenSecret: tokenSecret,
	}
	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		return err
	}
	return client.CheckTermProxySupport(ctx)
}

// resolveInstanceNode creates a temporary APIClient and resolves the
// Proxmox node name that should be stored with this instance.
//
// When sshHost is non-empty it is matched against the cluster node list
// (exact or FQDN-prefix match). When sshHost is empty and the cluster has
// exactly one node that node is used automatically; otherwise an error is
// returned asking the caller to supply --ssh-host for disambiguation.
func resolveInstanceNode(ctx context.Context, apiURL, tokenID, tokenSecret, sshHost string) (string, error) {
	inst := &models.ProxmoxInstance{
		APIURL:         apiURL,
		APITokenID:     tokenID,
		APITokenSecret: tokenSecret,
		SSHHost:        sshHost,
	}
	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		return "", err
	}
	return client.ResolveNodeName(ctx, sshHost)
}
