package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

func instanceCmd(deps *Deps) *ucli.Command { //nolint:gocognit,funlen // CLI command tree
	return &ucli.Command{
		Name:  "instance",
		Usage: "Manage Proxmox instances",
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
						fmt.Fprintf(deps.Out, "%-20s  API: %s  SSH: %s:%d\n",
							inst.Name, inst.APIURL, inst.SSHHost, inst.SSHPort)
					}
					return nil
				},
			},
			{
				Name:  cmdAdd,
				Usage: "Add a Proxmox instance",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagName, Required: true, Usage: "Instance name"},
					&ucli.StringFlag{Name: "api-url", Required: true, Usage: "Proxmox API URL (e.g. https://pve:8006)"},
					&ucli.StringFlag{Name: "token-id", Required: true, Usage: "API token ID (e.g. user@pam!token)"},
					&ucli.StringFlag{Name: "token-secret", Required: true, Usage: "API token secret"},
					&ucli.StringFlag{Name: "ssh-host", Required: true, Usage: "SSH host (host or host:port, default port 22)"},
					&ucli.StringFlag{Name: "ssh-user", Value: "root", Usage: "SSH username"},
					&ucli.StringFlag{Name: "ssh-key-path", Required: true, Usage: "Path to SSH private key"},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					sshHost, sshPort, err := parseHostPort(
						cmd.String("ssh-host"), 22)
					if err != nil {
						return fmt.Errorf("invalid --ssh-host: %w", err)
					}
					inst := &models.ProxmoxInstance{
						Name:           cmd.String(flagName),
						APIURL:         cmd.String("api-url"),
						APITokenID:     cmd.String("token-id"),
						APITokenSecret: cmd.String("token-secret"),
						SSHHost:        sshHost,
						SSHPort:        sshPort,
						SSHUser:        cmd.String("ssh-user"),
						SSHKeyPath:     cmd.String("ssh-key-path"),
					}
					if err := deps.Repo.AddProxmoxInstance(ctx, inst); err != nil {
						return err
					}
					fmt.Fprintf(deps.Out, "Instance %q added.\n", inst.Name)

					// Run discovery on the new instance.
					if deps.Discoverer != nil {
						// Re-read to get the DB-assigned ID.
						instances, err := deps.Repo.ListProxmoxInstances(ctx)
						if err != nil {
							return nil // non-fatal
						}
						for _, i := range instances {
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
						fmt.Fprintf(deps.Out, "SSH Host:         %s\n", inst.SSHHost)
						fmt.Fprintf(deps.Out, "SSH Port:         %d\n", inst.SSHPort)
						fmt.Fprintf(deps.Out, "SSH User:         %s\n", inst.SSHUser)
						fmt.Fprintf(deps.Out, "SSH Key Path:     %s\n", inst.SSHKeyPath)
					}
					return nil
				},
			},
		},
	}
}
