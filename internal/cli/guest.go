package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

func guestCmd(deps *Deps) *ucli.Command { //nolint:gocognit // CLI command tree
	return &ucli.Command{
		Name:   "guest",
		Usage:  "Manage and connect to guests",
		Action: unknownSubcmdAction,
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List discovered guests",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					guests, err := deps.Repo.ListGuests(ctx)
					if err != nil {
						return err
					}
					if cmd.String(flagFormat) == formatJSON {
						return json.NewEncoder(deps.Out).Encode(guests)
					}
					if len(guests) == 0 {
						fmt.Fprintln(deps.Out, "No guests discovered.")
						return nil
					}
					fmt.Fprintf(deps.Out, "%-6s %-6s %-24s %-10s %s\n",
						"TYPE", "VMID", "NAME", "STATUS", "INSTANCE")
					instances, _ := deps.Repo.ListProxmoxInstances(ctx)
					instMap := make(map[int64]string)
					for _, i := range instances {
						instMap[i.ID] = i.Name
					}
					for _, g := range guests {
						instName := instMap[g.InstanceID]
						if instName == "" {
							instName = fmt.Sprintf("(id:%d)", g.InstanceID)
						}
						fmt.Fprintf(deps.Out, "%-6s %-6d %-24s %-10s %s\n",
							g.Type, g.ProxmoxID, g.Name, g.Status, instName)
					}
					return nil
				},
			},
			{
				Name:      "connect",
				Usage:     "Connect to a guest console",
				ArgsUsage: "[<instance>:]<identifier>",
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					if cmd.NArg() < 1 {
						return fmt.Errorf(
							"usage: guest connect [<instance>:]<identifier>\n\n" +
								"identifier can be a VMID (e.g. 100), type+VMID (e.g. ct100), or name (e.g. webserver).\n" +
								"if multiple guests match, prefix with the instance name (e.g. rome:ct101)",
						)
					}
					target := cmd.Args().First()
					instName, identifier := ParseGuestTarget(target)

					guests, err := deps.Repo.ListGuests(ctx)
					if err != nil {
						return err
					}

					instances, err := deps.Repo.ListProxmoxInstances(ctx)
					if err != nil {
						return err
					}

					guest, inst, err := ResolveGuestAndInstance(identifier, instName, guests, instances)
					if err != nil {
						return err
					}

					deps.ConnectRequest = &ConnectRequest{
						Guest:    guest,
						Instance: inst,
					}
					return nil
				},
			},
			{
				Name:      cmdInspect,
				Usage:     "Show details for one or more guests",
				ArgsUsage: "<identifier> [<identifier> ...]",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					if cmd.NArg() == 0 {
						return fmt.Errorf("usage: guest inspect <identifier> [<identifier> ...]")
					}
					allGuests, err := deps.Repo.ListGuests(ctx)
					if err != nil {
						return err
					}
					instances, _ := deps.Repo.ListProxmoxInstances(ctx)
					instMap := make(map[int64]string, len(instances))
					for _, inst := range instances {
						instMap[inst.ID] = inst.Name
					}
					var found []*models.Guest
					for _, ident := range cmd.Args().Slice() {
						instName, id := ParseGuestTarget(ident)
						g, _, resolveErr := ResolveGuestAndInstance(id, instName, allGuests, instances)
						if resolveErr != nil {
							return resolveErr
						}
						found = append(found, g)
					}
					if cmd.String(flagFormat) == formatJSON {
						return json.NewEncoder(deps.Out).Encode(found)
					}
					for i, g := range found {
						if i > 0 {
							fmt.Fprintln(deps.Out)
						}
						instName := instMap[g.InstanceID]
						if instName == "" {
							instName = fmt.Sprintf("(id:%d)", g.InstanceID)
						}
						fmt.Fprintf(deps.Out, "Name:       %s\n", g.Name)
						fmt.Fprintf(deps.Out, "Type:       %s\n", g.Type)
						fmt.Fprintf(deps.Out, "VMID:       %d\n", g.ProxmoxID)
						fmt.Fprintf(deps.Out, "Status:     %s\n", g.Status)
						fmt.Fprintf(deps.Out, "Instance:   %s\n", instName)
					}
					return nil
				},
			},
		},
	}
}
