package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	ucli "github.com/urfave/cli/v3"
)

func adminKeyCmd(deps *Deps) *ucli.Command {
	return &ucli.Command{
		Name:   "admin-key",
		Usage:  "Manage admin SSH keys",
		Action: unknownSubcmdAction,
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List admin keys",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					keys, err := deps.Repo.ListAdminKeys(ctx)
					if err != nil {
						return err
					}
					if cmd.String(flagFormat) == formatJSON {
						return json.NewEncoder(deps.Out).Encode(keys)
					}
					if len(keys) == 0 {
						fmt.Fprintln(deps.Out, "No admin keys configured.")
						return nil
					}
					for i, k := range keys {
						fmt.Fprintf(deps.Out, "%d: %s\n",
							i+1, truncateKey(k))
					}
					return nil
				},
			},
			{
				Name:  cmdAdd,
				Usage: "Add one or more admin SSH public keys",
				Flags: []ucli.Flag{
					&ucli.StringSliceFlag{
						Name:     flagKey,
						Required: true,
						Usage:    "SSH public key — repeatable",
					},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					return forEachKey(
						cmd.StringSlice(flagKey), deps.Out,
						"added",
						func(k string) error {
							return deps.Repo.AddAdminKey(ctx, k)
						},
					)
				},
			},
			{
				Name:  cmdRm,
				Usage: "Remove one or more admin SSH public keys",
				Flags: []ucli.Flag{
					&ucli.StringSliceFlag{
						Name:     flagKey,
						Required: true,
						Usage:    "SSH public key — repeatable",
					},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					return forEachKey(
						cmd.StringSlice(flagKey), deps.Out,
						"removed",
						func(k string) error {
							return deps.Repo.RemoveAdminKey(ctx, k)
						},
					)
				},
			},
		},
	}
}

// forEachKey trims, validates, and applies fn to each key,
// printing a confirmation line for each.
func forEachKey(
	keys []string, out io.Writer, verb string,
	fn func(string) error,
) error {
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if err := fn(k); err != nil {
			return err
		}
		fmt.Fprintf(out, "Admin key %s: %s\n",
			verb, truncateKey(k))
	}
	return nil
}

func truncateKey(k string) string {
	if len(k) > 60 {
		return k[:60] + "..."
	}
	return k
}
