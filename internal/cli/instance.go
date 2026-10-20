package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"proxpass/internal/models"
	"proxpass/internal/proxmox"

	ucli "github.com/urfave/cli/v3"
)

func instanceCmd(deps *Deps) *ucli.Command { //nolint:gocognit,funlen // CLI command tree
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
						if inst.ConsoleTransport == models.ConsoleTransportSSH {
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
				Usage: "Add a Proxmox instance",
				Description: `Adds one Proxmox instance to proxpass.

  - --name optionally overrides the automatically resolved node name.
  - --ssh-host optionally sets the SSH host/port for node shell, SFTP and
    file transfer. Accepts "host" or "host:port" (port defaults to 22). It is
    NOT derived from --url; when omitted the instance has no SSH host and those
    features stay disabled until you set one with "instance update --ssh-host".
    The termproxy console works either way.`,
				Flags: []ucli.Flag{
					&ucli.StringFlag{
						Name:  flagName,
						Usage: "Instance name (if omitted the Proxmox node name is used)",
					},
					&ucli.StringFlag{
						Name:     "url",
						Required: true,
						Usage:    "Proxmox API URL (e.g. https://pve:8006)",
					},
					&ucli.StringFlag{Name: "token-id", Required: true, Usage: "API token ID (e.g. user@pam!token)"},
					&ucli.StringFlag{Name: "token-secret", Required: true, Usage: "API token secret"},
					&ucli.StringFlag{
						Name:  "console-transport",
						Value: string(models.ConsoleTransportTermProxy),
						Usage: `How a guest CONSOLE is attached: "termproxy" ` +
							`(default) or "ssh". Does not affect file ` +
							`transfer, which always reaches the node over SSH.`,
					},
					&ucli.StringFlag{
						Name: "ssh-host",
						Usage: "SSH host — \"host\" or \"host:port\"." +
							" Enables node shell, SFTP and file transfer; not derived" +
							" from --url, so when omitted the instance has no SSH host.",
					},
					&ucli.StringFlag{Name: "ssh-user", Value: "root", Usage: "SSH username"},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					rawURL := cmd.String("url")

					connType := models.ConsoleTransport(cmd.String("console-transport"))
					if connType != models.ConsoleTransportTermProxy && connType != models.ConsoleTransportSSH {
						return fmt.Errorf("--console-transport must be %q or %q", models.ConsoleTransportTermProxy, models.ConsoleTransportSSH)
					}

					if err := validateAPIURL(rawURL); err != nil {
						return err
					}

					// Validate --ssh-host up-front.
					if cmd.String("ssh-host") != "" {
						if _, _, err := parseHostPort(cmd.String("ssh-host"), 22); err != nil {
							return fmt.Errorf("invalid --ssh-host: %w", err)
						}
					}

					// The deployment's own key lives in a root-owned file this
					// session cannot read. Its public half, and the reachability
					// check that needs the private half, are obtained from
					// `proxpass serve' (root) through deps.SSHKeys inside
					// addInstance -- not read here. Instances no longer carry a key
					// of their own: its public half has to be installed on the
					// Proxmox host by hand, and a key per instance multiplies that
					// work without isolating anything.
					return addInstance(ctx, deps, cmd, connType, rawURL)
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
						// Case-insensitive, matching InstanceLookup and the
						// way an instance resolves inside a login name: it
						// would be odd for `access grant --instance ROME' to
						// work while `instance rm ROME' did not.
						if models.NamesEqual(inst.Name, name) {
							if err := deps.Repo.RemoveProxmoxInstance(ctx, inst.ID); err != nil {
								return err
							}
							fmt.Fprintf(deps.Out, "Instance %q removed.\n", inst.Name)
							return nil
						}
					}
					return fmt.Errorf("instance %q not found", name)
				},
			},
			instanceUpdateCmd(deps),
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
						byName[models.FoldName(inst.Name)] = inst
					}
					var found []*models.ProxmoxInstance
					for _, name := range cmd.Args().Slice() {
						inst, ok := byName[models.FoldName(name)]
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
						fmt.Fprintf(deps.Out, "Connection Type:  %s\n", inst.ConsoleTransport)
						fmt.Fprintf(deps.Out, "Node:             %s\n", inst.Node)
						if inst.ConsoleTransport == models.ConsoleTransportSSH {
							fmt.Fprintf(deps.Out, "SSH Host:         %s\n", inst.SSHHost)
							fmt.Fprintf(deps.Out, "SSH Port:         %d\n", inst.SSHPort)
							fmt.Fprintf(deps.Out, "SSH User:         %s\n", inst.SSHUser)
							reportSSHKey(ctx, deps, inst)
						}
					}
					return nil
				},
			},
		},
	}
}

// parseExplicitSSHHost parses the SSH host and port from an explicit
// --ssh-host value. An empty value yields an empty host and a zero port,
// deliberately: the SSH host is NEVER derived from --url, because the API URL
// is just as often a bare IP or an address that does not resolve from where
// proxpass runs. An instance with no SSH host is a valid, handled state --
// its termproxy console still works, and node shell / SFTP / file transfer
// are cleanly refused until an admin sets a host with `instance update
// --ssh-host`.
//
// A non-empty value is parsed as "host" or "host:port"; the port defaults to
// 22 when omitted.
func parseExplicitSSHHost(explicitSSHHost string) (host string, port int, err error) {
	if explicitSSHHost == "" {
		return "", 0, nil
	}
	h, p, parseErr := parseHostPort(explicitSSHHost, 22)
	if parseErr != nil {
		return "", 0, fmt.Errorf("invalid --ssh-host: %w", parseErr)
	}
	return h, p, nil
}

// addInstance adds the Proxmox instance described by the "instance add" flags.
func addInstance(
	ctx context.Context,
	deps *Deps,
	cmd *ucli.Command,
	connType models.ConsoleTransport,
	rawURL string,
) error {
	// Determine the SSH host and port.
	//
	// --ssh-host "host" or "host:port" is used as-is. When it is omitted the
	// instance has no SSH host at all: it is NEVER derived from --url, because
	// the API address is just as often a bare IP or an alias that does not
	// resolve from where proxpass runs. The termproxy console works without
	// it; node shell / SFTP / file transfer are cleanly refused until an admin
	// sets a host with `instance update --ssh-host`.
	sshHost, sshPort, err := parseExplicitSSHHost(cmd.String("ssh-host"))
	if err != nil {
		return err
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
	if connType == models.ConsoleTransportTermProxy {
		if err := checkTermProxyVersion(ctx, rawURL, cmd.String("token-id"), cmd.String("token-secret")); err != nil {
			return err
		}
	}

	instName := cmd.String(flagName)
	if instName == "" {
		// Name was not supplied: fall back to the resolved node name.
		instName = nodeName
	}

	inst := &models.ProxmoxInstance{
		Name:             instName,
		APIURL:           rawURL,
		APITokenID:       cmd.String("token-id"),
		APITokenSecret:   cmd.String("token-secret"),
		ConsoleTransport: connType,
		Node:             nodeName,
		SSHHost:          sshHost,
		SSHPort:          sshPort,
		SSHUser:          cmd.String("ssh-user"),
	}

	// Check that the key actually opens the host BEFORE storing anything,
	// so a mistake is reported against the command that made it rather than
	// against the first guest somebody tries to reach.
	//
	// A failure is NOT fatal, and that is deliberate: the administrator has
	// to install the public key on the host by hand, and they cannot do that
	// before an instance exists to tell them which host. Refusing here would
	// make the obvious order impossible. So it prints the key and what to do
	// with it, and adds the instance anyway.
	if connType == models.ConsoleTransportSSH && inst.SSHHost != "" {
		if err := deps.SSHKeys.CheckInstanceSSHAccess(ctx, inst); err != nil {
			pub, _, pubErr := deps.SSHKeys.SSHPublicKey(ctx)
			if pubErr != nil {
				return fmt.Errorf("deriving the public key: %w", pubErr)
			}
			fmt.Fprintf(deps.ErrOut,
				"Warning: %s is not reachable over SSH yet: %v\n"+
					"Add this key to %s on %s, then run `instance inspect %s' to re-check:\n%s",
				inst.SSHHost, err, authorizedKeysPath, inst.SSHHost, instName, pub)
		}
	}

	if err := deps.Repo.AddProxmoxInstance(ctx, inst); err != nil {
		return err
	}
	fmt.Fprintf(deps.Out, "Instance %q added (connection: %s, node: %s).\n", inst.Name, inst.ConsoleTransport, inst.Node)

	// Warn when there is no SSH host: the instance was still added (its console
	// may work), but node shell, SFTP and file transfer are unavailable until
	// a host is set. No-op when a host is present.
	warnMissingSSHHost(ctx, deps, inst)

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
			// Shared with the discovery loop: only running guests are
			// stored, so the list cannot contain an unconnectable guest.
			stored, _, err := proxmox.StoreGuests(ctx, deps.Repo, i, guests)
			if err != nil {
				fmt.Fprintf(deps.ErrOut, "Storing guests: %v\n", err)
			}
			fmt.Fprintf(deps.Out, "Discovered %d guests, %d running.\n", len(guests), stored)
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
// (exact or FQDN-prefix match). When sshHost is empty, or when it matches no
// node, the node that served the API request (--api-url points at exactly one
// node) is used. See proxmox.APIClient.ResolveNodeName.
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
