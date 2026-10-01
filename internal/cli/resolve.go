package cli

import (
	"errors"
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
	// An unqualified target may be qualified, so suggesting the prefix is
	// useful advice.
	return ResolveGuestAndInstanceHinted(
		identifier, instName, guests, instances, instName == "")
}

// ResolveGuestAndInstanceHinted is ResolveGuestAndInstance with explicit
// control over the disambiguation hint.
//
// hintInstance must be false where the caller's syntax cannot express an
// instance prefix -- a login name cannot contain a colon -- so that an
// ambiguity error does not advise something impossible.
func ResolveGuestAndInstanceHinted(
	identifier string,
	instName string,
	guests []*models.Guest,
	instances []*models.ProxmoxInstance,
	hintInstance bool,
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

	instNames := make(map[int64]string, len(instances))
	for _, inst := range instances {
		instNames[inst.ID] = inst.Name
	}
	guest, err := resolveGuest(identifier, pool, instNames, hintInstance)
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
func ResolveGuest(
	identifier string,
	guests []*models.Guest,
	hintInstance bool,
) (*models.Guest, error) {
	return resolveGuest(identifier, guests, nil, hintInstance)
}

// resolveGuest is ResolveGuest with the instance names used to describe an
// ambiguity; see ambiguousError.
func resolveGuest(
	identifier string,
	guests []*models.Guest,
	instNames map[int64]string,
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
			return nil, ambiguousError(identifier, matches, instNames, hintInstance)
		}
		// No match by VMID; fall through to other methods.
	}

	// --- 2. Try type+VMID (e.g. "ct100", "vm200") ---
	//
	// A VMID is unique per instance but NOT across them, so "ct100" can match
	// a guest on two different instances. This used to return whichever came
	// first, silently connecting to an arbitrary one of them; it now reports
	// the ambiguity like the other two tiers do.
	for _, prefix := range []models.GuestType{
		models.GuestTypeCT, models.GuestTypeVM,
	} {
		p := string(prefix)
		if !strings.HasPrefix(lower, p) {
			continue
		}
		vmid, err := strconv.Atoi(lower[len(p):])
		if err != nil {
			continue
		}
		var matches []*models.Guest
		for _, g := range guests {
			if g.Type == prefix && g.ProxmoxID == vmid {
				matches = append(matches, g)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		if len(matches) > 1 {
			return nil, ambiguousError(
				fmt.Sprintf("%s%d", p, vmid), matches, instNames, hintInstance)
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
		return nil, ambiguousError(identifier, matches, instNames, hintInstance)
	}

	return nil, fmt.Errorf("%w: %q", ErrGuestNotFound, identifier)
}

// ErrGuestNotFound reports that an identifier matched no guest at all, as
// opposed to matching several.
//
// The distinction matters where a miss is not a failure: a login name that
// happens not to name a guest falls back to the picker, while an ambiguous
// one has to be reported rather than guessed at. See
// session.connectByLoginName.
var ErrGuestNotFound = errors.New("guest not found")

// ambiguousError reports that identifier matched more than one guest, and
// suggests how to narrow it down.
//
// When the caller accepts an "instance:identifier" target, that prefix is
// the advice: a VMID and a type+VMID are already as specific as a bare
// identifier gets, so nothing else would help.
//
// Otherwise the hint has to name the alternatives concretely. It lists
// "instance:typeVMID" per match, because the distinguishing part may be the
// instance: listing bare ids for an ambiguous "ct100" would print "ct100,
// ct100" and tell the user nothing. instNames may be nil, in which case
// only the ids are listed.
func ambiguousError(
	identifier string,
	matches []*models.Guest,
	instNames map[int64]string,
	hintInstance bool,
) error {
	if hintInstance {
		return fmt.Errorf(
			"%q matches %d guests; use instance:identifier (see 'guest ls')",
			identifier, len(matches))
	}
	hints := make([]string, 0, len(matches))
	for _, g := range matches {
		id := fmt.Sprintf("%s%d", g.Type, g.ProxmoxID)
		if inst := instNames[g.InstanceID]; inst != "" {
			id = inst + ":" + id
		}
		hints = append(hints, id)
	}
	return fmt.Errorf("%q matches %d guests: %s",
		identifier, len(matches), strings.Join(hints, ", "))
}
