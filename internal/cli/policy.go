package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

func policyCmd(deps *Deps) *ucli.Command { //nolint:gocognit // CLI command tree
	return &ucli.Command{
		Name:  "policy",
		Usage: "Manage default access policy",
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List default policy entries",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					policy, err := deps.Repo.GetDefaultPolicy(ctx)
					if err != nil {
						return err
					}
					if cmd.String(flagFormat) == formatJSON {
						return json.NewEncoder(deps.Out).Encode(policy)
					}
					if policy == nil || (len(policy.AuthorizedClientIDs) == 0 && len(policy.AuthorizedGroupIDs) == 0) {
						fmt.Fprintln(deps.Out, "Default policy: deny all (no entries).")
						return nil
					}
					clients, _ := deps.Repo.ListClients(ctx)
					groups, _ := deps.Repo.ListGroups(ctx)
					clientMap := make(map[int64]string)
					for _, c := range clients {
						clientMap[c.ID] = c.Name
					}
					groupMap := make(map[int64]string)
					for _, g := range groups {
						groupMap[g.ID] = g.Name
					}
					for _, id := range policy.AuthorizedClientIDs {
						name := clientMap[id]
						if name == "" {
							name = fmt.Sprintf("(id:%d)", id)
						}
						fmt.Fprintf(deps.Out, "client  %s\n", name)
					}
					for _, id := range policy.AuthorizedGroupIDs {
						name := groupMap[id]
						if name == "" {
							name = fmt.Sprintf("(id:%d)", id)
						}
						fmt.Fprintf(deps.Out, "group   %s\n", name)
					}
					return nil
				},
			},
			{
				Name:  cmdAdd,
				Usage: "Add a client or group to the default policy",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagClient, Usage: usageClientName},
					&ucli.StringFlag{Name: flagGroup, Usage: usageGroupName},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					clientName := cmd.String("client")
					groupName := cmd.String("group")
					if (clientName == "") == (groupName == "") {
						return fmt.Errorf("specify exactly one of --client or --group")
					}

					policy, err := deps.Repo.GetDefaultPolicy(ctx)
					if err != nil {
						return err
					}
					if policy == nil {
						policy = &models.DefaultAccessPolicy{}
					}

					ruleType, subjectID, err := resolveSubject(ctx, deps, clientName, groupName)
					if err != nil {
						return err
					}
					if ruleType == models.RuleClient {
						policy.AuthorizedClientIDs = appendUnique(policy.AuthorizedClientIDs, subjectID)
						fmt.Fprintf(deps.Out, "Client %q added to default policy.\n", clientName)
					} else {
						policy.AuthorizedGroupIDs = appendUnique(policy.AuthorizedGroupIDs, subjectID)
						fmt.Fprintf(deps.Out, "Group %q added to default policy.\n", groupName)
					}
					return deps.Repo.SetDefaultPolicy(ctx, policy)
				},
			},
			{
				Name:  cmdRm,
				Usage: "Remove a client or group from the default policy",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagClient, Usage: usageClientName},
					&ucli.StringFlag{Name: flagGroup, Usage: usageGroupName},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					clientName := cmd.String(flagClient)
					groupName := cmd.String(flagGroup)
					if (clientName == "") == (groupName == "") {
						return fmt.Errorf("specify exactly one of --client or --group")
					}

					policy, err := deps.Repo.GetDefaultPolicy(ctx)
					if err != nil {
						return err
					}
					if policy == nil {
						return fmt.Errorf("default policy is empty")
					}

					ruleType, subjectID, err := resolveSubject(ctx, deps, clientName, groupName)
					if err != nil {
						return err
					}
					if ruleType == models.RuleClient {
						policy.AuthorizedClientIDs = removeInt64(policy.AuthorizedClientIDs, subjectID)
						fmt.Fprintf(deps.Out, "Client %q removed from default policy.\n", clientName)
					} else {
						policy.AuthorizedGroupIDs = removeInt64(policy.AuthorizedGroupIDs, subjectID)
						fmt.Fprintf(deps.Out, "Group %q removed from default policy.\n", groupName)
					}
					return deps.Repo.SetDefaultPolicy(ctx, policy)
				},
			},
		},
	}
}

// resolveSubject resolves a client or group name to a rule type and subject ID.
func resolveSubject(ctx context.Context, deps *Deps, clientName, groupName string) (models.RuleType, int64, error) {
	if clientName != "" {
		client, err := deps.Repo.GetClientByName(ctx, clientName)
		if err != nil || client == nil {
			return "", 0, fmt.Errorf("client %q not found", clientName)
		}
		return models.RuleClient, client.ID, nil
	}
	groups, err := deps.Repo.ListGroups(ctx)
	if err != nil {
		return "", 0, err
	}
	for _, g := range groups {
		if g.Name == groupName {
			return models.RuleGroup, g.ID, nil
		}
	}
	return "", 0, fmt.Errorf("group %q not found", groupName)
}

func appendUnique(ids []int64, id int64) []int64 {
	for _, existing := range ids {
		if existing == id {
			return ids
		}
	}
	return append(ids, id)
}

func removeInt64(ids []int64, id int64) []int64 {
	result := make([]int64, 0, len(ids))
	for _, existing := range ids {
		if existing != id {
			result = append(result, existing)
		}
	}
	return result
}
