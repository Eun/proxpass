package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

func clientCmd(deps *Deps) *ucli.Command { //nolint:gocognit // CLI command tree
	return &ucli.Command{
		Name:  flagClient,
		Usage: "Manage SSH clients",
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List clients",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					clients, err := deps.Repo.ListClients(ctx)
					if err != nil {
						return err
					}
					if cmd.String(flagFormat) == formatJSON {
						return json.NewEncoder(deps.Out).Encode(clients)
					}
					if len(clients) == 0 {
						fmt.Fprintln(deps.Out, "No clients configured.")
						return nil
					}
					for _, c := range clients {
						keys := len(c.PublicKeys)
						groups := len(c.GroupIDs)
						fmt.Fprintf(deps.Out, "%-20s  %d key(s)  %d group(s)\n",
							c.Name, keys, groups)
					}
					return nil
				},
			},
			{
				Name:  cmdAdd,
				Usage: "Add a client",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagName, Required: true, Usage: usageClientName},
					&ucli.StringSliceFlag{Name: flagKey, Required: true, Usage: "SSH public key (repeatable)"},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					name := cmd.String("name")
					keys := cmd.StringSlice("key")
					if len(keys) == 0 {
						return fmt.Errorf("at least one --key is required")
					}
					// Trim whitespace
					var trimmed []string
					for _, k := range keys {
						k = strings.TrimSpace(k)
						if k != "" {
							trimmed = append(trimmed, k)
						}
					}
					if len(trimmed) == 0 {
						return fmt.Errorf("at least one non-empty --key is required")
					}
					c := &models.Client{Name: name, PublicKeys: trimmed}
					if err := deps.Repo.AddClient(ctx, c); err != nil {
						return err
					}
					fmt.Fprintf(deps.Out, "Client %q added with %d key(s).\n", name, len(trimmed))
					return nil
				},
			},
			{ //nolint:dupl // rm commands share structure across entity types
				Name:  cmdRm,
				Usage: "Remove a client",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagName, Required: true, Usage: usageClientName},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					name := cmd.String("name")
					clients, err := deps.Repo.ListClients(ctx)
					if err != nil {
						return err
					}
					for _, c := range clients {
						if c.Name == name {
							if err := deps.Repo.RemoveClient(ctx, c.ID); err != nil {
								return err
							}
							fmt.Fprintf(deps.Out, "Client %q removed.\n", name)
							return nil
						}
					}
					return fmt.Errorf("client %q not found", name)
				},
			},
			{
				Name:      cmdInspect,
				Usage:     "Show details for one or more clients",
				ArgsUsage: argsNames,
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					if cmd.NArg() == 0 {
						return fmt.Errorf("usage: client inspect <name> [<name> ...]")
					}
					clients, err := deps.Repo.ListClients(ctx)
					if err != nil {
						return err
					}
					groups, _ := deps.Repo.ListGroups(ctx)
					groupMap := make(map[int64]string, len(groups))
					for _, g := range groups {
						groupMap[g.ID] = g.Name
					}
					byName := make(map[string]*models.Client, len(clients))
					for _, c := range clients {
						byName[c.Name] = c
					}
					var found []*models.Client
					for _, name := range cmd.Args().Slice() {
						c, ok := byName[name]
						if !ok {
							return fmt.Errorf("client %q not found", name)
						}
						found = append(found, c)
					}
					if cmd.String(flagFormat) == formatJSON {
						return json.NewEncoder(deps.Out).Encode(found)
					}
					for i, c := range found {
						if i > 0 {
							fmt.Fprintln(deps.Out)
						}
						fmt.Fprintf(deps.Out, "Name:    %s\n", c.Name)
						fmt.Fprintf(deps.Out, "Keys:    %d\n", len(c.PublicKeys))
						for j, k := range c.PublicKeys {
							fmt.Fprintf(deps.Out, "  Key %d: %s\n", j+1, k)
						}
						if len(c.GroupIDs) > 0 {
							fmt.Fprint(deps.Out, "Groups:  ")
							for j, gid := range c.GroupIDs {
								if j > 0 {
									fmt.Fprint(deps.Out, ", ")
								}
								name := groupMap[gid]
								if name == "" {
									name = fmt.Sprintf("(id:%d)", gid)
								}
								fmt.Fprint(deps.Out, name)
							}
							fmt.Fprintln(deps.Out)
						}
					}
					return nil
				},
			},
		},
	}
}
