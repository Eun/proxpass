package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

func guestCmd(deps *Deps) *ucli.Command { //nolint:gocognit // CLI command tree
	return &ucli.Command{
		Name:   "guest",
		Usage:  "Manage and connect to guests",
		Action: unknownSubcmdAction,
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List discovered guests",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					guests, err := deps.Repo.ListGuests(ctx)
					if err != nil {
						return err
					}
					if cmd.String(flagFormat) == formatJSON {
						return json.NewEncoder(deps.Out).Encode(guests)
					}
					if len(guests) == 0 {
						fmt.Fprintln(deps.Out, "No guests discovered.")
						return nil
					}
					fmt.Fprintf(deps.Out, "%-6s %-6s %-24s %-10s %s\n",
						"TYPE", "VMID", "NAME", "STATUS", "INSTANCE")
					instances, _ := deps.Repo.ListProxmoxInstances(ctx)
					instMap := make(map[int64]string)
					for _, i := range instances {
						instMap[i.ID] = i.Name
					}
					for _, g := range guests {
						instName := instMap[g.InstanceID]
						if instName == "" {
							instName = fmt.Sprintf("(id:%d)", g.InstanceID)
						}
						fmt.Fprintf(deps.Out, "%-6s %-6d %-24s %-10s %s\n",
							g.Type, g.ProxmoxID, g.Name, g.Status, instName)
					}
					return nil
				},
			},
			{
				Name:      "connect",
				Usage:     "Connect to a guest console",
				ArgsUsage: "[<instance>:]<identifier>",
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					if cmd.NArg() < 1 {
						return fmt.Errorf(
							"usage: guest connect [<instance>:]<identifier>\n\n" +
								"identifier can be a VMID (e.g. 100), type+VMID (e.g. ct100), or name (e.g. webserver).\n" +
								"if multiple guests match, prefix with the instance name (e.g. rome:ct101)",
						)
					}
					target := cmd.Args().First()
					instName, identifier := parseGuestTarget(target)

					guests, err := deps.Repo.ListGuests(ctx)
					if err != nil {
						return err
					}

					instances, err := deps.Repo.ListProxmoxInstances(ctx)
					if err != nil {
						return err
					}

					guest, inst, err := resolveGuestAndInstance(identifier, instName, guests, instances)
					if err != nil {
						return err
					}

					deps.ConnectRequest = &ConnectRequest{
						Guest:    guest,
						Instance: inst,
					}
					return nil
				},
			},
			{
				Name:      cmdInspect,
				Usage:     "Show details for one or more guests",
				ArgsUsage: "<identifier> [<identifier> ...]",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					if cmd.NArg() == 0 {
						return fmt.Errorf("usage: guest inspect <identifier> [<identifier> ...]")
					}
					allGuests, err := deps.Repo.ListGuests(ctx)
					if err != nil {
						return err
					}
					instances, _ := deps.Repo.ListProxmoxInstances(ctx)
					instMap := make(map[int64]string, len(instances))
					for _, inst := range instances {
						instMap[inst.ID] = inst.Name
					}
					var found []*models.Guest
					for _, ident := range cmd.Args().Slice() {
						instName, id := parseGuestTarget(ident)
						g, _, resolveErr := resolveGuestAndInstance(id, instName, allGuests, instances)
						if resolveErr != nil {
							return resolveErr
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
						instName := instMap[g.InstanceID]
						if instName == "" {
							instName = fmt.Sprintf("(id:%d)", g.InstanceID)
						}
						fmt.Fprintf(deps.Out, "Name:       %s\n", g.Name)
						fmt.Fprintf(deps.Out, "Type:       %s\n", g.Type)
						fmt.Fprintf(deps.Out, "VMID:       %d\n", g.ProxmoxID)
						fmt.Fprintf(deps.Out, "Status:     %s\n", g.Status)
						fmt.Fprintf(deps.Out, "Instance:   %s\n", instName)
					}
					return nil
				},
			},
		},
	}
}

// parseGuestTarget splits an optional "instance:identifier" string.
// If no colon is present, instanceName is empty.
func parseGuestTarget(s string) (instanceName, identifier string) {
	if idx := strings.IndexByte(s, ':'); idx >= 0 {
		return s[:idx], s[idx+1:]
	}
	return "", s
}

// resolveGuestAndInstance looks up a guest and its Proxmox instance by
// identifier and optional instance name filter.
//
// If instName is non-empty, only guests on that instance are considered.
// If multiple guests match, an error is returned hinting to use instance:identifier.
func resolveGuestAndInstance(
	identifier string,
	instName string,
	guests []*models.Guest,
	instances []*models.ProxmoxInstance,
) (*models.Guest, *models.ProxmoxInstance, error) {
	// Build instance lookup map by ID.
	instByID := make(map[int64]*models.ProxmoxInstance, len(instances))
	var instFilterID int64 = -1 // -1 means no filter
	switch {
	case instName != "":
		found := false
		for _, inst := range instances {
			instByID[inst.ID] = inst
			if strings.EqualFold(inst.Name, instName) {
				instFilterID = inst.ID
				found = true
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("instance %q not found", instName)
		}
	default:
		for _, inst := range instances {
			instByID[inst.ID] = inst
		}
	}

	// Filter guests by instance if a filter was given.
	var pool []*models.Guest
	if instFilterID >= 0 {
		for _, g := range guests {
			if g.InstanceID == instFilterID {
				pool = append(pool, g)
			}
		}
	} else {
		pool = guests
	}

	guest, err := resolveGuest(identifier, pool, instName == "" /* hintInstance*/)
	if err != nil {
		return nil, nil, err
	}

	inst := instByID[guest.InstanceID]
	if inst == nil {
		return nil, nil, fmt.Errorf("proxmox instance for guest %q not found", guest.Name)
	}
	return guest, inst, nil
}

// resolveGuest looks up a guest by identifier within the given pool.
// Resolution order: numeric VMID → type+VMID (ct100, vm200) ‒ name.
//
// hintInstance controls whether error messages suggest using the
// instance:identifier format to disambiguate.
//
//nolint:gocognit,nestif // resolution logic
func resolveGuest(identifier string, guests []*models.Guest, hintInstance bool) (*models.Guest, error) {
	lower := strings.ToLower(identifier)

	// 1. Numeric VMID
	if vmid, err := strconv.Atoi(identifier); err == nil {
		var matches []*models.Guest
		for _, g := range guests {
			if g.ProxmoxID == vmid {
				matches = append(matches, g)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		if len(matches) > 1 {
			if hintInstance {
				return nil, fmt.Errorf(
					"VMID %d matches %d guests; use instance:identifier (see 'guest ls')",
					vmid, len(matches))
			}
			return nil, fmt.Errorf(
				"VMID %d matches %d guests; use type+id (e.g. %s%d)",
				vmid, len(matches), matches[0].Type, vmid)
		}
	}

	// 2. Type+VMID
	for _, prefix := range []models.GuestType{models.GuestTypeCT, models.GuestTypeVM} {
		p := string(prefix)
		if strings.HasPrefix(lower, p) {
			if vmid, err := strconv.Atoi(lower[len(p):]); err == nil {
				for _, g := range guests {
					if g.Type == prefix && g.ProxmoxID == vmid {
						return g, nil
					}
				}
			}
		}
	}

	// 3. Name (case-insensitive)
	var matches []*models.Guest
	for _, g := range guests {
		if strings.EqualFold(g.Name, identifier) {
			matches = append(matches, g)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		if hintInstance {
			return nil, fmt.Errorf(
				"name %q matches %d guests; use instance:identifier (see 'guest ls')",
				identifier, len(matches))
		}
		var hints []string
		for _, g := range matches {
			hints = append(hints, fmt.Sprintf("%s%d", g.Type, g.ProxmoxID))
		}
		return nil, fmt.Errorf(
			"name %q matches %d guests; use: %s",
			identifier, len(matches), strings.Join(hints, ", "))
	}

	return nil, fmt.Errorf("guest %q not found", identifier)
}
