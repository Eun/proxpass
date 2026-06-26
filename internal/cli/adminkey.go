package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	ucli "github.com/urfave/cli/v3"
)

func adminKeyCmd(deps *Deps) *ucli.Command {
	return &ucli.Command{
		Name:  "admin-key",
		Usage: "Manage admin SSH keys",
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List admin keys",
				Flags: []ucli.Flag{
					&ucli.BoolFlag{Name: flagJSON, Usage: usageJSON},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					keys, err := deps.Repo.ListAdminKeys(ctx)
					if err != nil {
						return err
					}
					if cmd.Bool("json") {
						return json.NewEncoder(deps.Out).Encode(keys)
					}
					if len(keys) == 0 {
						fmt.Fprintln(deps.Out, "No admin keys configured.")
						return nil
					}
					for i, k := range keys {
						// Show truncated key for readability
						short := k
						if len(k) > 60 {
							short = k[:60] + "..."
						}
						fmt.Fprintf(deps.Out, "%d: %s\n", i+1, short)
					}
					return nil
				},
			},
			{
				Name:  cmdAdd,
				Usage: "Add an admin SSH public key",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagKey, Required: true, Usage: "SSH public key (authorized_keys format)"},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					key := strings.TrimSpace(cmd.String("key"))
					if key == "" {
						return fmt.Errorf("key cannot be empty")
					}
					if err := deps.Repo.AddAdminKey(ctx, key); err != nil {
						return err
					}
					fmt.Fprintln(deps.Out, "Admin key added.")
					return nil
				},
			},
			{
				Name:  cmdRm,
				Usage: "Remove an admin SSH public key",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagKey, Required: true, Usage: "SSH public key to remove"},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					key := strings.TrimSpace(cmd.String("key"))
					if key == "" {
						return fmt.Errorf("key cannot be empty")
					}
					if err := deps.Repo.RemoveAdminKey(ctx, key); err != nil {
						return err
					}
					fmt.Fprintln(deps.Out, "Admin key removed.")
					return nil
				},
			},
		},
	}
}
