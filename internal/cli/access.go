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
		Name:   "access",
		Usage:  "Manage access rules",
		Action: unknownSubcmdAction,
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
				Usage: "Grant access to guests or to a Proxmox node",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagClient, Usage: usageClientName},
					&ucli.StringFlag{Name: flagGroup, Usage: usageGroupName},
					// Neither target flag is Required: one of the two must
					// be given, which urfave cannot express, so the check
					// is in targetsFrom.
					&ucli.StringSliceFlag{
						Name:  flagGuest,
						Usage: "Guest identifier — repeatable (VMID, type+VMID, or name)",
					},
					&ucli.StringSliceFlag{
						Name:  flagInstance,
						Usage: usageInstanceTarget,
					},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					return grantAccess(ctx, deps, cmd)
				},
			},
			{
				Name:  "revoke",
				Usage: "Revoke access to guests or to a Proxmox node",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagClient, Usage: usageClientName},
					&ucli.StringFlag{Name: flagGroup, Usage: usageGroupName},
					&ucli.StringSliceFlag{
						Name:  flagGuest,
						Usage: "Guest identifier — repeatable",
					},
					&ucli.StringSliceFlag{
						Name:  flagInstance,
						Usage: usageInstanceTarget,
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
	instRules, err := deps.Repo.ListInstanceAccessRules(ctx)
	if err != nil {
		return err
	}
	if cmd.String(flagFormat) == formatJSON {
		// An object with two arrays rather than one merged list. The rows
		// have different shapes -- guest_id against instance_id -- and a
		// consumer that only understands guests keeps reading "guests"
		// unchanged rather than meeting fields it cannot interpret.
		return json.NewEncoder(deps.Out).Encode(struct {
			Guests    []*models.AccessRuleRow         `json:"guests"`
			Instances []*models.InstanceAccessRuleRow `json:"instances"`
		}{Guests: rules, Instances: instRules})
	}
	if len(rules) == 0 && len(instRules) == 0 {
		fmt.Fprintln(deps.Out, "No access rules configured.")
		return nil
	}

	clients, _ := deps.Repo.ListClients(ctx)
	groups, _ := deps.Repo.ListGroups(ctx)
	guests, _ := deps.Repo.ListGuests(ctx)
	instances, _ := deps.Repo.ListProxmoxInstances(ctx)
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
	instMap := make(map[int64]string, len(instances))
	for _, inst := range instances {
		instMap[inst.ID] = inst.Name
	}

	subjectOf := func(t models.RuleType, id int64) string {
		var subject string
		switch t {
		case models.RuleClient:
			subject = clientMap[id]
		case models.RuleGroup:
			subject = groupMap[id]
		}
		if subject == "" {
			// A rule whose subject is gone. Shown rather than hidden: it
			// is still in the table and still worth revoking.
			return fmt.Sprintf("(id:%d)", id)
		}
		return subject
	}

	// A TARGET column names what each rule points at, and a KIND column
	// says which sort of thing that is. Without KIND a node and a guest
	// that share a name would print identically, and they grant very
	// different things.
	const layout = "%-8s %-20s %-8s %-30s\n"
	fmt.Fprintf(deps.Out, layout, "TYPE", "SUBJECT", "KIND", "TARGET")
	for _, r := range rules {
		target := guestMap[r.GuestID]
		if target == "" {
			target = fmt.Sprintf("(id:%d)", r.GuestID)
		}
		fmt.Fprintf(deps.Out, layout,
			r.Type, subjectOf(r.Type, r.SubjectID), "guest", target)
	}
	for _, r := range instRules {
		target := instMap[r.InstanceID]
		if target == "" {
			target = fmt.Sprintf("(id:%d)", r.InstanceID)
		}
		fmt.Fprintf(deps.Out, layout,
			r.Type, subjectOf(r.Type, r.SubjectID), "node", target)
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
	instances, err := deps.Repo.ListProxmoxInstances(ctx)
	if err != nil {
		return nil, nil, err
	}
	known := InstanceLookup(instances)
	ids = make([]int64, 0, len(identifiers))
	names = make([]string, 0, len(identifiers))
	for _, ident := range identifiers {
		// Accept the qualified form too. Without it a VMID that exists on
		// two instances could not be granted AT ALL: ambiguous unqualified,
		// and there was no way to qualify it here.
		instName, id := ParseGuestTarget(ident, known)
		g, _, resolveErr := ResolveGuestAndInstance(
			id, instName, allGuests, instances)
		if resolveErr != nil {
			return nil, nil, resolveErr
		}
		ids = append(ids, g.ID)
		names = append(names, g.Name)
	}
	return ids, names, nil
}

// resolveInstanceNames resolves instance names to their database ids.
//
// Matching is case-insensitive, like InstanceLookup and like instance
// resolution in a login name. `instance add' stores whatever case the
// administrator typed, so requiring an exact match here would let a grant
// fail for a node that `<name>@proxpass' reaches perfectly well.
func resolveInstanceNames(
	ctx context.Context, deps *Deps, names []string,
) (ids []int64, resolved []string, err error) {
	instances, err := deps.Repo.ListProxmoxInstances(ctx)
	if err != nil {
		return nil, nil, err
	}
	ids = make([]int64, 0, len(names))
	resolved = make([]string, 0, len(names))
	for _, name := range names {
		var match *models.ProxmoxInstance
		for _, inst := range instances {
			if models.NamesEqual(inst.Name, name) {
				match = inst
				break
			}
		}
		if match == nil {
			return nil, nil, fmt.Errorf("instance %q not found", name)
		}
		ids = append(ids, match.ID)
		// The stored name, not what was typed, so the confirmation shows
		// what the rule actually points at.
		resolved = append(resolved, match.Name)
	}
	return ids, resolved, nil
}

// accessTargets is what a grant or revoke was asked to act on.
//
// Guests and instances are carried separately rather than merged, because
// they are stored in different tables and reached by different calls. Names
// travel alongside the ids purely so the confirmation can name what changed.
type accessTargets struct {
	guestIDs    []int64
	guestNames  []string
	instanceIDs []int64
	instNames   []string
}

// targetsFrom reads and validates the target flags shared by grant and
// revoke.
//
// Both may be given at once: `--guest web --instance rome' is two rules in
// one command, and refusing it would only make the administrator type the
// command twice. At least one is required, which urfave's Required cannot
// express across a pair of flags -- hence the check here rather than in the
// flag definition.
func targetsFrom(
	ctx context.Context, deps *Deps, cmd *ucli.Command,
) (*accessTargets, error) {
	guestIdents := cmd.StringSlice(flagGuest)
	instIdents := cmd.StringSlice(flagInstance)
	if len(guestIdents) == 0 && len(instIdents) == 0 {
		return nil, fmt.Errorf("specify at least one --guest or --instance")
	}

	t := &accessTargets{}
	var err error
	if len(guestIdents) > 0 {
		t.guestIDs, t.guestNames, err = resolveGuestIdentifiers(ctx, deps, guestIdents)
		if err != nil {
			return nil, err
		}
	}
	if len(instIdents) > 0 {
		t.instanceIDs, t.instNames, err = resolveInstanceNames(ctx, deps, instIdents)
		if err != nil {
			return nil, err
		}
	}
	return t, nil
}

// subjectKind names which sort of subject a rule belongs to, and is the word
// the confirmation line uses.
const (
	subjectClient = "client"
	subjectGroup  = "group"
)

// subjectFrom resolves the --client or --group a rule belongs to, returning
// its id and the word for the confirmation line.
func subjectFrom(
	ctx context.Context, deps *Deps, cmd *ucli.Command,
) (id int64, kind, name string, err error) {
	clientName := cmd.String(flagClient)
	groupName := cmd.String(flagGroup)
	if (clientName == "") == (groupName == "") {
		return 0, "", "", fmt.Errorf("specify exactly one of --client or --group")
	}
	if clientName != "" {
		client, lookupErr := deps.Repo.GetClientByName(ctx, clientName)
		if lookupErr != nil {
			return 0, "", "", fmt.Errorf("client %q: %w", clientName, lookupErr)
		}
		if client == nil {
			return 0, "", "", fmt.Errorf("client %q not found", clientName)
		}
		return client.ID, subjectClient, clientName, nil
	}
	grp, lookupErr := findGroupByName(ctx, deps, groupName)
	if lookupErr != nil {
		return 0, "", "", lookupErr
	}
	return grp.ID, subjectGroup, groupName, nil
}

func grantAccess(
	ctx context.Context, deps *Deps, cmd *ucli.Command,
) error {
	subjectID, kind, subjectName, err := subjectFrom(ctx, deps, cmd)
	if err != nil {
		return err
	}
	targets, err := targetsFrom(ctx, deps, cmd)
	if err != nil {
		return err
	}

	grantGuests := deps.Repo.GrantClientAccess
	grantInstances := deps.Repo.GrantClientInstanceAccess
	if kind == subjectGroup {
		grantGuests = deps.Repo.GrantGroupAccess
		grantInstances = deps.Repo.GrantGroupInstanceAccess
	}

	if len(targets.guestIDs) > 0 {
		if err := grantGuests(ctx, subjectID, targets.guestIDs); err != nil {
			return err
		}
		for _, name := range targets.guestNames {
			fmt.Fprintf(deps.Out, "Granted %s %q access to %s.\n",
				kind, subjectName, name)
		}
	}
	if len(targets.instanceIDs) > 0 {
		if err := grantInstances(ctx, subjectID, targets.instanceIDs); err != nil {
			return err
		}
		for _, name := range targets.instNames {
			// Named as a node, so a reader of the output can tell this
			// line apart from a guest that happens to share the name.
			fmt.Fprintf(deps.Out, "Granted %s %q access to node %s.\n",
				kind, subjectName, name)
		}
	}
	return nil
}

func revokeAccess(
	ctx context.Context, deps *Deps, cmd *ucli.Command,
) error {
	subjectID, kind, subjectName, err := subjectFrom(ctx, deps, cmd)
	if err != nil {
		return err
	}
	targets, err := targetsFrom(ctx, deps, cmd)
	if err != nil {
		return err
	}

	revokeGuest := deps.Repo.RevokeClientAccess
	revokeInstance := deps.Repo.RevokeClientInstanceAccess
	if kind == subjectGroup {
		revokeGuest = deps.Repo.RevokeGroupAccess
		revokeInstance = deps.Repo.RevokeGroupInstanceAccess
	}

	for i, guestID := range targets.guestIDs {
		if err := revokeGuest(ctx, subjectID, guestID); err != nil {
			return err
		}
		fmt.Fprintf(deps.Out, "Revoked %s %q access to %s.\n",
			kind, subjectName, targets.guestNames[i])
	}
	for i, instID := range targets.instanceIDs {
		if err := revokeInstance(ctx, subjectID, instID); err != nil {
			return err
		}
		fmt.Fprintf(deps.Out, "Revoked %s %q access to node %s.\n",
			kind, subjectName, targets.instNames[i])
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
	// Case-insensitive; see resolveSubject in policy.go for why this is
	// safe only now that names are unique ignoring case.
	for _, g := range groups {
		if models.NamesEqual(g.Name, name) {
			return g, nil
		}
	}
	return nil, fmt.Errorf("group %q not found", name)
}
