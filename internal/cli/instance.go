package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
	gossh "golang.org/x/crypto/ssh"
)

func instanceCmd(deps *Deps) *ucli.Command { //nolint:gocognit,funlen,gocyclo // CLI command tree
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
					&ucli.StringFlag{
						Name:  "ssh-key-path",
						Usage: "Path to SSH private key on the proxpass server (mutually exclusive with --ssh-key, --generate-ssh-key)",
					},
					&ucli.StringFlag{
						Name:  "ssh-key",
						Usage: "PEM-encoded private key content (mutually exclusive with --ssh-key-path, --generate-ssh-key)",
					},
					&ucli.BoolFlag{
						Name:  "generate-ssh-key",
						Usage: "Generate a new ED25519 key pair; prints the public key to add to Proxmox authorized_keys",
					},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					generateKey := cmd.Bool("generate-ssh-key")
					keyPath := cmd.String("ssh-key-path")
					keyInline := cmd.String("ssh-key")

					// Exactly one key source must be supplied.
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
						return fmt.Errorf("one of --ssh-key-path, --ssh-key, or --generate-ssh-key is required")
					}
					if set > 1 {
						return fmt.Errorf("--ssh-key-path, --ssh-key, and --generate-ssh-key are mutually exclusive")
					}

					// Validate api-url before storing: scheme must be http/https
					// and a port must be explicitly specified.
					// (Without a scheme, url.Parse treats the host as the scheme
					// and silently drops the port; without a port, requests go
					// to the scheme default: 80 or 443.)
					if err := validateAPIURL(cmd.String("api-url")); err != nil {
						return err
					}

					sshHost, sshPort, err := parseHostPort(
						cmd.String("ssh-host"), 22)
					if err != nil {
						return fmt.Errorf("invalid --ssh-host: %w", err)
					}

					var sshKeyPEM string
					var pubKeyAuthorized string
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

					inst := &models.ProxmoxInstance{
						Name:           cmd.String(flagName),
						APIURL:         cmd.String("api-url"),
						APITokenID:     cmd.String("token-id"),
						APITokenSecret: cmd.String("token-secret"),
						SSHHost:        sshHost,
						SSHPort:        sshPort,
						SSHUser:        cmd.String("ssh-user"),
						SSHKeyPath:     keyPath,
						SSHKey:         sshKeyPEM,
					}
					if err := deps.Repo.AddProxmoxInstance(ctx, inst); err != nil {
						return err
					}
					fmt.Fprintf(deps.Out, "Instance %q added.\n", inst.Name)
					if pubKeyAuthorized != "" {
						fmt.Fprintf(deps.Out, "Public key (add to Proxmox authorized_keys on %s):\n%s", inst.SSHHost, pubKeyAuthorized)
					}

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
						if inst.SSHKey != "" {
							fmt.Fprintf(deps.Out, "SSH Key:          (generated, stored in DB)\n")
						} else {
							fmt.Fprintf(deps.Out, "SSH Key Path:     %s\n", inst.SSHKeyPath)
						}
					}
					return nil
				},
			},
		},
	}
}
