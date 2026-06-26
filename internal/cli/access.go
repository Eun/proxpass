package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

func accessCmd(deps *Deps) *ucli.Command { //nolint:gocognit,gocyclo,funlen // CLI command tree
	return &ucli.Command{
		Name:  "access",
		Usage: "Manage access rules",
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List access rules",
				Flags: []ucli.Flag{
					&ucli.BoolFlag{Name: flagJSON, Usage: usageJSON},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					rules, err := deps.Repo.ListAccessRules(ctx)
					if err != nil {
						return err
					}
					if cmd.Bool("json") {
						return json.NewEncoder(deps.Out).Encode(rules)
					}
					if len(rules) == 0 {
						fmt.Fprintln(deps.Out, "No access rules configured.")
						return nil
					}
					// Build name maps
					clients, _ := deps.Repo.ListClients(ctx)
					groups, _ := deps.Repo.ListGroups(ctx)
					guests, _ := deps.Repo.ListGuests(ctx)
					clientMap := make(map[int64]string)
					for _, c := range clients {
						clientMap[c.ID] = c.Name
					}
					groupMap := make(map[int64]string)
					for _, g := range groups {
						groupMap[g.ID] = g.Name
					}
					guestMap := make(map[int64]string)
					for _, g := range guests {
						guestMap[g.ID] = fmt.Sprintf("%s (%s%d)", g.Name, g.Type, g.ProxmoxID)
					}
					fmt.Fprintf(deps.Out, "%-8s %-20s %-30s\n", "TYPE", "SUBJECT", "GUEST")
					for _, r := range rules {
						var subject string
						switch r.Type {
						case models.RuleClient:
							subject = clientMap[r.SubjectID]
						case models.RuleGroup:
							subject = groupMap[r.SubjectID]
						}
						if subject == "" {
							subject = fmt.Sprintf("(id:%d)", r.SubjectID)
						}
						guest := guestMap[r.GuestID]
						if guest == "" {
							guest = fmt.Sprintf("(id:%d)", r.GuestID)
						}
						fmt.Fprintf(deps.Out, "%-8s %-20s %-30s\n", r.Type, subject, guest)
					}
					return nil
				},
			},
			{
				Name:  "grant",
				Usage: "Grant access to a guest",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagClient, Usage: usageClientName},
					&ucli.StringFlag{Name: flagGroup, Usage: usageGroupName},
					&ucli.StringFlag{Name: flagGuest, Required: true, Usage: "Guest identifier (VMID, type+VMID, or name)"},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					clientName := cmd.String("client")
					groupName := cmd.String("group")
					guestIdent := cmd.String("guest")

					if (clientName == "") == (groupName == "") {
						return fmt.Errorf("specify exactly one of --client or --group")
					}

					// Resolve guest
					guests, err := deps.Repo.ListGuests(ctx)
					if err != nil {
						return err
					}
					guest, err := resolveGuest(guestIdent, guests)
					if err != nil {
						return err
					}

					if clientName != "" { //nolint:nestif // client-or-group branching
						client, err := deps.Repo.GetClientByName(ctx, clientName)
						if err != nil {
							return fmt.Errorf("client %q: %w", clientName, err)
						}
						if client == nil {
							return fmt.Errorf("client %q not found", clientName)
						}
						if err := deps.Repo.GrantClientAccess(ctx, client.ID, []int64{guest.ID}); err != nil {
							return err
						}
						fmt.Fprintf(deps.Out, "Granted client %q access to %s.\n", clientName, guest.Name)
					} else {
						groups, err := deps.Repo.ListGroups(ctx)
						if err != nil {
							return err
						}
						var grp *models.Group
						for _, g := range groups {
							if g.Name == groupName {
								grp = g
								break
							}
						}
						if grp == nil {
							return fmt.Errorf("group %q not found", groupName)
						}
						if err := deps.Repo.GrantGroupAccess(ctx, grp.ID, []int64{guest.ID}); err != nil {
							return err
						}
						fmt.Fprintf(deps.Out, "Granted group %q access to %s.\n", groupName, guest.Name)
					}
					return nil
				},
			},
			{
				Name:  "revoke",
				Usage: "Revoke access to a guest",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagClient, Usage: usageClientName},
					&ucli.StringFlag{Name: flagGroup, Usage: usageGroupName},
					&ucli.StringFlag{Name: flagGuest, Required: true, Usage: "Guest identifier"},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					clientName := cmd.String("client")
					groupName := cmd.String("group")
					guestIdent := cmd.String("guest")

					if (clientName == "") == (groupName == "") {
						return fmt.Errorf("specify exactly one of --client or --group")
					}

					guests, err := deps.Repo.ListGuests(ctx)
					if err != nil {
						return err
					}
					guest, err := resolveGuest(guestIdent, guests)
					if err != nil {
						return err
					}

					if clientName != "" { //nolint:nestif // client-or-group branching
						client, err := deps.Repo.GetClientByName(ctx, clientName)
						if err != nil {
							return fmt.Errorf("client %q: %w", clientName, err)
						}
						if client == nil {
							return fmt.Errorf("client %q not found", clientName)
						}
						if err := deps.Repo.RevokeClientAccess(ctx, client.ID, guest.ID); err != nil {
							return err
						}
						fmt.Fprintf(deps.Out, "Revoked client %q access to %s.\n", clientName, guest.Name)
					} else {
						groups, err := deps.Repo.ListGroups(ctx)
						if err != nil {
							return err
						}
						var grp *models.Group
						for _, g := range groups {
							if g.Name == groupName {
								grp = g
								break
							}
						}
						if grp == nil {
							return fmt.Errorf("group %q not found", groupName)
						}
						if err := deps.Repo.RevokeGroupAccess(ctx, grp.ID, guest.ID); err != nil {
							return err
						}
						fmt.Fprintf(deps.Out, "Revoked group %q access to %s.\n", groupName, guest.Name)
					}
					return nil
				},
			},
		},
	}
}
