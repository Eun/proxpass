package cli

import (
	"fmt"
	"strconv"
	"strings"

	"proxpass/internal/models"
)

// ParseGuestTarget splits an optional "instance:identifier" string.
// If no colon is present, instanceName is empty.
func ParseGuestTarget(s string) (instanceName, identifier string) {
	if idx := strings.IndexByte(s, ':'); idx >= 0 {
		return s[:idx], s[idx+1:]
	}
	return "", s
}

// ResolveGuestAndInstance looks up a guest and its Proxmox instance by
// identifier and an optional instance name filter.
//
// If instName is non-empty, only guests on that instance are considered.
// If multiple guests match, an error is returned hinting to use instance:identifier.
func ResolveGuestAndInstance(
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

	guest, err := ResolveGuest(identifier, pool, instName == "" /* hintInstance*/)
	if err != nil {
		return nil, nil, err
	}

	inst := instByID[guest.InstanceID]
	if inst == nil {
		return nil, nil, fmt.Errorf("proxmox instance for guest %q not found", guest.Name)
	}
	return guest, inst, nil
}

// ResolveGuest looks up a guest by identifier within the given pool.
// Resolution order: numeric VMID → type+VMID (ct100, vm200) ‒ name.
//
// hintInstance controls whether error messages suggest using the
// instance:identifier format to disambiguate.
//
//nolint:gocognit,nestif // sequential resolution tiers require nested checks
func ResolveGuest(
	identifier string,
	guests []*models.Guest,
	hintInstance bool,
) (*models.Guest, error) {
	lower := strings.ToLower(identifier)

	// --- 1. Try numeric VMID ---
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
				"VMID %d matches %d guests; use type+id instead (e.g. %s%d)",
				vmid, len(matches), matches[0].Type, vmid)
		}
		// No match by VMID; fall through to other methods.
	}

	// --- 2. Try type+VMID (e.g. "ct100", "vm200") ---
	for _, prefix := range []models.GuestType{
		models.GuestTypeCT, models.GuestTypeVM,
	} {
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

	// --- 3. Try guest name (case-insensitive) ---
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
			"name %q matches %d guests; use a unique id: %s",
			identifier, len(matches), strings.Join(hints, ", "))
	}

	return nil, fmt.Errorf("guest %q not found", identifier)
}
