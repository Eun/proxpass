package cli

import (
	"context"
	"fmt"

	ucli "github.com/urfave/cli/v3"

	"proxpass/internal/models"
)

// instanceUpdateCmd changes settings on an instance that already exists.
//
// Without it an instance was write-once: a Proxmox host moving to a new
// address, a rotated API token, or an SSH daemon on a different port all
// meant removing the instance and adding it again -- which discards its
// access rules, because they are keyed on the instance.
//
// # Only what is named changes
//
// Each flag is applied only when it was actually given on the command line,
// not when it merely holds its zero value. That distinction is the whole
// design: `instance update --name pve1 --ssh-port 2222' must not also blank
// the API token because --token-secret was absent. urfave/cli reports it
// through IsSet, which tells "--ssh-user ”" apart from an omitted flag -- so
// a field CAN still be deliberately cleared where that makes sense.
func instanceUpdateCmd(deps *Deps) *ucli.Command {
	return &ucli.Command{
		Name:  cmdUpdate,
		Usage: "Change settings on an existing Proxmox instance",
		Description: `Updates one Proxmox instance in place, leaving its access rules intact.

Only the flags you pass are changed; everything else keeps its stored value.

  instance update --name pve1 --ssh-host pve1.internal:2222
  instance update --name pve1 --token-id "user@pam!new" --token-secret "uuid"
  instance update --name pve1 --rename pve-old

Changing --url or --ssh-host re-resolves the Proxmox node name, because the
stored one describes the host that was there before.`,
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name:     flagName,
				Required: true,
				Usage:    "Name of the instance to update",
			},
			&ucli.StringFlag{
				Name:  "rename",
				Usage: "New name for the instance",
			},
			&ucli.StringFlag{
				Name:  "url",
				Usage: "Proxmox API URL (e.g. https://pve:8006)",
			},
			&ucli.StringFlag{Name: "token-id", Usage: "API token ID"},
			&ucli.StringFlag{Name: "token-secret", Usage: "API token secret"},
			&ucli.StringFlag{
				Name: "console-transport",
				Usage: `How a guest CONSOLE is attached: "termproxy" or ` +
					`"ssh". Does not affect file transfer.`,
			},
			&ucli.StringFlag{
				Name:  "ssh-host",
				Usage: `SSH host — "host" or "host:port"`,
			},
			&ucli.StringFlag{Name: "ssh-user", Usage: "SSH username"},
		},
		Action: func(ctx context.Context, cmd *ucli.Command) error {
			return runInstanceUpdate(ctx, deps, cmd)
		},
	}
}

func runInstanceUpdate(ctx context.Context, deps *Deps, cmd *ucli.Command) error {
	name := cmd.String(flagName)
	inst, err := findInstanceByName(ctx, deps, name)
	if err != nil {
		return err
	}

	// Remember whether the host moved, which decides below whether the
	// stored node name still describes the right machine.
	hostChanged := cmd.IsSet("url") || cmd.IsSet("ssh-host")

	if err := applyInstanceFlags(cmd, inst); err != nil {
		return err
	}

	// Re-resolve the node name when the host moved. The stored one was
	// resolved against the OLD address, so keeping it would leave the
	// instance pointing at a node that may not be there -- and every guest
	// lookup goes through it.
	if hostChanged {
		node, resolveErr := resolveInstanceNode(
			ctx, inst.APIURL, inst.APITokenID, inst.APITokenSecret, inst.SSHHost)
		if resolveErr != nil {
			return fmt.Errorf("resolving node name for %s: %w", inst.APIURL, resolveErr)
		}
		inst.Node = node
	}

	if err := deps.Repo.UpdateProxmoxInstance(ctx, inst); err != nil {
		return err
	}
	fmt.Fprintf(deps.Out, "Instance %q updated.\n", inst.Name)

	// Report reachability the same way `instance add' does, so a change that
	// breaks SSH is visible now rather than at the next transfer.
	reportSSHKey(ctx, deps, inst)
	return nil
}

// applyInstanceFlags copies the flags that were given onto inst.
func applyInstanceFlags(cmd *ucli.Command, inst *models.ProxmoxInstance) error {
	if cmd.IsSet("rename") {
		newName := cmd.String("rename")
		if newName == "" {
			return fmt.Errorf("--rename cannot be empty")
		}
		inst.Name = newName
	}
	if cmd.IsSet("url") {
		rawURL := cmd.String("url")
		if err := validateAPIURL(rawURL); err != nil {
			return err
		}
		inst.APIURL = rawURL
		// Re-derive the SSH host: it came from the OLD url, so leaving it
		// would point the instance's API at one machine and its file
		// transfers at another.
		//
		// An explicit --ssh-host overrides this, by being applied after --
		// see the ordering note at the end of this function.
		host, port, err := resolveSSHHostPort("", rawURL, false)
		if err != nil {
			return err
		}
		inst.SSHHost, inst.SSHPort = host, port
	}
	if cmd.IsSet("token-id") {
		inst.APITokenID = cmd.String("token-id")
	}
	if cmd.IsSet("token-secret") {
		inst.APITokenSecret = cmd.String("token-secret")
	}
	if cmd.IsSet("console-transport") {
		transport := models.ConsoleTransport(cmd.String("console-transport"))
		if transport != models.ConsoleTransportTermProxy &&
			transport != models.ConsoleTransportSSH {
			return fmt.Errorf("--console-transport must be %q or %q",
				models.ConsoleTransportTermProxy, models.ConsoleTransportSSH)
		}
		inst.ConsoleTransport = transport
	}
	// AFTER the --url branch, deliberately: --url re-derives the SSH host,
	// and an explicit --ssh-host must win over that derivation when both are
	// given. Moving this above --url would silently reverse that.
	if cmd.IsSet("ssh-host") {
		host, port, err := parseHostPort(cmd.String("ssh-host"), 22)
		if err != nil {
			return fmt.Errorf("invalid --ssh-host: %w", err)
		}
		inst.SSHHost, inst.SSHPort = host, port
	}
	if cmd.IsSet("ssh-user") {
		user := cmd.String("ssh-user")
		if user == "" {
			return fmt.Errorf("--ssh-user cannot be empty")
		}
		inst.SSHUser = user
	}
	return nil
}

// findInstanceByName returns the instance with that name.
func findInstanceByName(ctx context.Context, deps *Deps, name string) (*models.ProxmoxInstance, error) {
	instances, err := deps.Repo.ListProxmoxInstances(ctx)
	if err != nil {
		return nil, err
	}
	for _, inst := range instances {
		if inst.Name == name {
			return inst, nil
		}
	}
	return nil, fmt.Errorf("instance %q not found", name)
}
