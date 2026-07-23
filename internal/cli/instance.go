package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

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

When a single --url is supplied:
  - --name optionally overrides the automatically resolved node name.
  - --ssh-host optionally overrides the SSH host/port derived from --url.
    Accepts "host" or "host:port"; when omitted, the hostname from --url is
    used with the default SSH port (22).

When multiple --url flags are supplied:
  - --name is disallowed; each instance is named after its Proxmox node name.
  - --ssh-host is disallowed; each instance's SSH host is derived from the
    hostname in its --url, with the default SSH port (22).`,
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
						Usage: "SSH host — \"host\" or \"host:port\" (--connection-type ssh, single --url only)." +
							" When omitted the hostname from --url is used with port 22." +
							" Disallowed when multiple --url flags are given.",
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
					multiURL := len(urls) > 1

					// --name and --ssh-host are both disallowed with multiple --url.
					if multiURL && cmd.String(flagName) != "" {
						return fmt.Errorf(
							"--name cannot be used when multiple --url flags are specified;" +
								" each instance will be named after its Proxmox node name",
						)
					}
					if multiURL && cmd.String("ssh-host") != "" {
						return fmt.Errorf(
							"--ssh-host cannot be used when multiple --url flags are specified;" +
								" the SSH host is derived from the hostname in each --url",
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

					// Validate --ssh-host (single --url only) up-front.
					if cmd.String("ssh-host") != "" {
						if _, _, err := parseHostPort(cmd.String("ssh-host"), 22); err != nil {
							return fmt.Errorf("invalid --ssh-host: %w", err)
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

// sshHostFromURL extracts the hostname (without port) from a Proxmox API URL
// for use as the default SSH host when --ssh-host is not specified.
// e.g. "https://pve1:8006" -> "pve1".
func sshHostFromURL(rawURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil {
		return "", err
	}
	host := parsed.Hostname() // strips port if present
	if host == "" {
		return "", fmt.Errorf("cannot derive SSH host from URL %q: missing host", rawURL)
	}
	return host, nil
}

// resolveSSHHostPort determines the SSH host and port for a single instance.
//
// When multiURL is true (or explicitSSHHost is empty) the SSH host is derived
// from the hostname in rawURL and the port defaults to 22.
// When explicitSSHHost is non-empty it is parsed as "host" or "host:port".
func resolveSSHHostPort(explicitSSHHost, rawURL string, multiURL bool) (host string, port int, err error) {
	if !multiURL && explicitSSHHost != "" {
		// Explicit --ssh-host: parse it, honoring an optional :port.
		h, p, parseErr := parseHostPort(explicitSSHHost, 22)
		if parseErr != nil {
			return "", 0, fmt.Errorf("invalid --ssh-host: %w", parseErr)
		}
		return h, p, nil
	}
	// Derive SSH host from the API URL hostname; always use port 22.
	h, urlErr := sshHostFromURL(rawURL)
	if urlErr != nil {
		return "", 0, fmt.Errorf("deriving SSH host from --url: %w", urlErr)
	}
	return h, 22, nil
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
	multiURL := len(cmd.StringSlice("url")) > 1

	// Determine the SSH host and port.
	//
	// Priority (single --url):
	//   1. --ssh-host "host" or "host:port"  → use as-is
	//   2. (omitted)                          → hostname from --url, port 22
	//
	// Multiple --url: always derive from --url hostname, port 22.
	// (--ssh-host is already rejected above for the multi-URL case.)
	var sshHost string
	var sshPort int
	if connType == models.ConnectionTypeSSH {
		var err error
		sshHost, sshPort, err = resolveSSHHostPort(cmd.String("ssh-host"), rawURL, multiURL)
		if err != nil {
			return err
		}
	}

	// Resolve the node name from the API.
	// Pass only the bare hostname as the hint (no port) so ResolveNodeName
	// can match it against the cluster node list correctly.
	nodeName, err := resolveInstanceNode(ctx, rawURL, cmd.String("token-id"), cmd.String("token-secret"), sshHost)
	if err != nil {
		return fmt.Errorf("resolving node name for %s: %w", rawURL, err)
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
