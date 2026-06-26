package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

func groupCmd(deps *Deps) *ucli.Command { //nolint:gocognit,funlen // CLI command tree
	return &ucli.Command{
		Name:  flagGroup,
		Usage: "Manage client groups",
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List groups",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					groups, err := deps.Repo.ListGroups(ctx)
					if err != nil {
						return err
					}
					if cmd.String(flagFormat) == formatJSON {
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
			{
				Name:      cmdInspect,
				Usage:     "Show details for one or more groups",
				ArgsUsage: argsNames,
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					if cmd.NArg() == 0 {
						return fmt.Errorf("usage: group inspect <name> [<name> ...]")
					}
					groups, err := deps.Repo.ListGroups(ctx)
					if err != nil {
						return err
					}
					clients, _ := deps.Repo.ListClients(ctx)
					clientMap := make(map[int64]string, len(clients))
					for _, c := range clients {
						clientMap[c.ID] = c.Name
					}
					byName := make(map[string]*models.Group, len(groups))
					for _, g := range groups {
						byName[g.Name] = g
					}
					var found []*models.Group
					for _, name := range cmd.Args().Slice() {
						g, ok := byName[name]
						if !ok {
							return fmt.Errorf("group %q not found", name)
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
						fmt.Fprintf(deps.Out, "Name:     %s\n", g.Name)
						fmt.Fprintf(deps.Out, "Members:  %d\n", len(g.ClientIDs))
						for _, cid := range g.ClientIDs {
							name := clientMap[cid]
							if name == "" {
								name = fmt.Sprintf("(id:%d)", cid)
							}
							fmt.Fprintf(deps.Out, "  - %s\n", name)
						}
					}
					return nil
				},
			},
		},
	}
}
