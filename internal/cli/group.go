package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

func groupCmd(deps *Deps) *ucli.Command { //nolint:gocognit // CLI command tree
	return &ucli.Command{
		Name:  flagGroup,
		Usage: "Manage client groups",
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List groups",
				Flags: []ucli.Flag{
					&ucli.BoolFlag{Name: flagJSON, Usage: usageJSON},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					groups, err := deps.Repo.ListGroups(ctx)
					if err != nil {
						return err
					}
					if cmd.Bool("json") {
						return json.NewEncoder(deps.Out).Encode(groups)
					}
					if len(groups) == 0 {
						fmt.Fprintln(deps.Out, "No groups configured.")
						return nil
					}
					// Resolve member names
					clients, _ := deps.Repo.ListClients(ctx)
					clientMap := make(map[int64]string)
					for _, c := range clients {
						clientMap[c.ID] = c.Name
					}
					for _, g := range groups {
						var members []string
						for _, id := range g.ClientIDs {
							if name, ok := clientMap[id]; ok {
								members = append(members, name)
							}
						}
						memberStr := "(none)"
						if len(members) > 0 {
							memberStr = fmt.Sprintf("%v", members)
						}
						fmt.Fprintf(deps.Out, "%-20s  members: %s\n", g.Name, memberStr)
					}
					return nil
				},
			},
			{
				Name:  cmdAdd,
				Usage: "Add a group",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagName, Required: true, Usage: usageGroupName},
					&ucli.StringSliceFlag{Name: "member", Usage: "Client name to add as member (repeatable)"},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					name := cmd.String("name")
					memberNames := cmd.StringSlice("member")

					var clientIDs []int64
					if len(memberNames) > 0 {
						clients, err := deps.Repo.ListClients(ctx)
						if err != nil {
							return err
						}
						clientMap := make(map[string]int64)
						for _, c := range clients {
							clientMap[c.Name] = c.ID
						}
						for _, m := range memberNames {
							id, ok := clientMap[m]
							if !ok {
								return fmt.Errorf("client %q not found", m)
							}
							clientIDs = append(clientIDs, id)
						}
					}

					g := &models.Group{Name: name, ClientIDs: clientIDs}
					if err := deps.Repo.AddGroup(ctx, g); err != nil {
						return err
					}
					fmt.Fprintf(deps.Out, "Group %q added with %d member(s).\n", name, len(clientIDs))
					return nil
				},
			},
			{ //nolint:dupl // rm commands share structure across entity types
				Name:  cmdRm,
				Usage: "Remove a group",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagName, Required: true, Usage: usageGroupName},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					name := cmd.String("name")
					groups, err := deps.Repo.ListGroups(ctx)
					if err != nil {
						return err
					}
					for _, g := range groups {
						if g.Name == name {
							if err := deps.Repo.RemoveGroup(ctx, g.ID); err != nil {
								return err
							}
							fmt.Fprintf(deps.Out, "Group %q removed.\n", name)
							return nil
						}
					}
					return fmt.Errorf("group %q not found", name)
				},
			},
		},
	}
}
