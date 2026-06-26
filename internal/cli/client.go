package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

func clientCmd(deps *Deps) *ucli.Command {
	return &ucli.Command{
		Name:  flagClient,
		Usage: "Manage SSH clients",
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List clients",
				Flags: []ucli.Flag{
					&ucli.BoolFlag{Name: flagJSON, Usage: usageJSON},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					clients, err := deps.Repo.ListClients(ctx)
					if err != nil {
						return err
					}
					if cmd.Bool("json") {
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
		},
	}
}
