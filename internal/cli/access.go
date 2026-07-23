package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

func accessCmd(deps *Deps) *ucli.Command {
	return &ucli.Command{
		Name:  "access",
		Usage: "Manage access rules",
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List access rules",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					return listAccessRules(ctx, deps, cmd)
				},
			},
			{
				Name:  "grant",
				Usage: "Grant access to one or more guests",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagClient, Usage: usageClientName},
					&ucli.StringFlag{Name: flagGroup, Usage: usageGroupName},
					&ucli.StringSliceFlag{
						Name:     flagGuest,
						Required: true,
						Usage:    "Guest identifier — repeatable (VMID, type+VMID, or name)",
					},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					return grantAccess(ctx, deps, cmd)
				},
			},
			{
				Name:  "revoke",
				Usage: "Revoke access to one or more guests",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagClient, Usage: usageClientName},
					&ucli.StringFlag{Name: flagGroup, Usage: usageGroupName},
					&ucli.StringSliceFlag{
						Name:     flagGuest,
						Required: true,
						Usage:    "Guest identifier — repeatable",
					},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					return revokeAccess(ctx, deps, cmd)
				},
			},
		},
	}
}

func listAccessRules(
	ctx context.Context, deps *Deps, cmd *ucli.Command,
) error {
	rules, err := deps.Repo.ListAccessRules(ctx)
	if err != nil {
		return err
	}
	if cmd.String(flagFormat) == formatJSON {
		return json.NewEncoder(deps.Out).Encode(rules)
	}
	if len(rules) == 0 {
		fmt.Fprintln(deps.Out, "No access rules configured.")
		return nil
	}

	clients, _ := deps.Repo.ListClients(ctx)
	groups, _ := deps.Repo.ListGroups(ctx)
	guests, _ := deps.Repo.ListGuests(ctx)
	clientMap := make(map[int64]string, len(clients))
	for _, c := range clients {
		clientMap[c.ID] = c.Name
	}
	groupMap := make(map[int64]string, len(groups))
	for _, g := range groups {
		groupMap[g.ID] = g.Name
	}
	guestMap := make(map[int64]string, len(guests))
	for _, g := range guests {
		guestMap[g.ID] = fmt.Sprintf(
			"%s (%s%d)", g.Name, g.Type, g.ProxmoxID)
	}

	fmt.Fprintf(deps.Out, "%-8s %-20s %-30s\n",
		"TYPE", "SUBJECT", "GUEST")
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
		fmt.Fprintf(deps.Out, "%-8s %-20s %-30s\n",
			r.Type, subject, guest)
	}
	return nil
}

// resolveGuestIdentifiers resolves multiple guest identifiers to
// their database IDs and returns both the IDs and a display-friendly
// list of names.
func resolveGuestIdentifiers(
	ctx context.Context,
	deps *Deps,
	identifiers []string,
) (ids []int64, names []string, err error) {
	allGuests, err := deps.Repo.ListGuests(ctx)
	if err != nil {
		return nil, nil, err
	}
	ids = make([]int64, 0, len(identifiers))
	names = make([]string, 0, len(identifiers))
	for _, ident := range identifiers {
		g, resolveErr := resolveGuest(ident, allGuests, false)
		if resolveErr != nil {
			return nil, nil, resolveErr
		}
		ids = append(ids, g.ID)
		names = append(names, g.Name)
	}
	return ids, names, nil
}

func grantAccess(
	ctx context.Context, deps *Deps, cmd *ucli.Command,
) error {
	clientName := cmd.String(flagClient)
	groupName := cmd.String(flagGroup)
	guestIdents := cmd.StringSlice(flagGuest)

	if (clientName == "") == (groupName == "") {
		return fmt.Errorf(
			"specify exactly one of --client or --group")
	}

	guestIDs, guestNames, err := resolveGuestIdentifiers(
		ctx, deps, guestIdents)
	if err != nil {
		return err
	}

	if clientName != "" { //nolint:nestif // client-or-group branch
		client, lookupErr := deps.Repo.GetClientByName(
			ctx, clientName)
		if lookupErr != nil {
			return fmt.Errorf("client %q: %w", clientName, lookupErr)
		}
		if client == nil {
			return fmt.Errorf("client %q not found", clientName)
		}
		if err := deps.Repo.GrantClientAccess(
			ctx, client.ID, guestIDs); err != nil {
			return err
		}
		for _, name := range guestNames {
			fmt.Fprintf(deps.Out,
				"Granted client %q access to %s.\n",
				clientName, name)
		}
	} else {
		grp, lookupErr := findGroupByName(ctx, deps, groupName)
		if lookupErr != nil {
			return lookupErr
		}
		if err := deps.Repo.GrantGroupAccess(
			ctx, grp.ID, guestIDs); err != nil {
			return err
		}
		for _, name := range guestNames {
			fmt.Fprintf(deps.Out,
				"Granted group %q access to %s.\n",
				groupName, name)
		}
	}
	return nil
}

func revokeAccess(
	ctx context.Context, deps *Deps, cmd *ucli.Command,
) error {
	clientName := cmd.String(flagClient)
	groupName := cmd.String(flagGroup)
	guestIdents := cmd.StringSlice(flagGuest)

	if (clientName == "") == (groupName == "") {
		return fmt.Errorf(
			"specify exactly one of --client or --group")
	}

	guestIDs, guestNames, err := resolveGuestIdentifiers(
		ctx, deps, guestIdents)
	if err != nil {
		return err
	}

	if clientName != "" { //nolint:nestif // client-or-group branch
		client, lookupErr := deps.Repo.GetClientByName(
			ctx, clientName)
		if lookupErr != nil {
			return fmt.Errorf("client %q: %w", clientName, lookupErr)
		}
		if client == nil {
			return fmt.Errorf("client %q not found", clientName)
		}
		for i, guestID := range guestIDs {
			if revokeErr := deps.Repo.RevokeClientAccess(
				ctx, client.ID, guestID); revokeErr != nil {
				return revokeErr
			}
			fmt.Fprintf(deps.Out,
				"Revoked client %q access to %s.\n",
				clientName, guestNames[i])
		}
	} else {
		grp, lookupErr := findGroupByName(ctx, deps, groupName)
		if lookupErr != nil {
			return lookupErr
		}
		for i, guestID := range guestIDs {
			if revokeErr := deps.Repo.RevokeGroupAccess(
				ctx, grp.ID, guestID); revokeErr != nil {
				return revokeErr
			}
			fmt.Fprintf(deps.Out,
				"Revoked group %q access to %s.\n",
				groupName, guestNames[i])
		}
	}
	return nil
}

func findGroupByName(
	ctx context.Context, deps *Deps, name string,
) (*models.Group, error) {
	groups, err := deps.Repo.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.Name == name {
			return g, nil
		}
	}
	return nil, fmt.Errorf("group %q not found", name)
}
