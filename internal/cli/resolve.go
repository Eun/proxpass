package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"proxpass/internal/models"
)

// ParseGuestTarget splits an optional "identifier@instance" string.
//
// The instance is the SUFFIX, so the target reads left to right the way it
// is spoken: "ct100@rome" is ct100 on rome. It is also the only split that
// works, because the separator has to be "@":
//
//   - a colon cannot appear in a login name at all (it is the passwd field
//     separator, so api.ValidLoginName rejects it), which is what made the
//     old "instance:identifier" form unusable as "ssh rome:ct100@host".
//   - "@" is already a legal login name character, and ssh splits user@host
//     on the LAST "@", so "ct100@rome@host" arrives with the username
//     "ct100@rome" intact. Verified against the image.
//
// The split is on the last "@" rather than the first for a specific reason:
// a guest name may itself contain "@" (names come from Proxmox and are not
// validated), while a Proxmox node name is a DNS hostname and cannot. So
// the suffix is unambiguous and the prefix keeps whatever "@" it had --
// "mail@corp@rome" is the guest "mail@corp" on "rome".
//
// knownInstance decides whether the suffix really is an instance. Without
// it, the client name "tobias@corp" -- valid today -- would be read as the
// guest "tobias" on an instance "corp". It may be nil, in which case no
// split is attempted and the whole string is one identifier.
func ParseGuestTarget(
	s string, knownInstance func(string) bool,
) (instanceName, identifier string) {
	if knownInstance == nil {
		return "", s
	}
	idx := strings.LastIndexByte(s, '@')
	if idx <= 0 || idx == len(s)-1 {
		// No "@", or nothing on one side of it: not a qualified target.
		return "", s
	}
	suffix := s[idx+1:]
	if !knownInstance(suffix) {
		// The suffix names no instance, so the "@" belongs to the
		// identifier itself.
		return "", s
	}
	return suffix, s[:idx]
}

// InstanceLookup returns a knownInstance predicate for ParseGuestTarget.
//
// Matching is case-insensitive, like instance resolution itself.
func InstanceLookup(instances []*models.ProxmoxInstance) func(string) bool {
	return func(name string) bool {
		for _, inst := range instances {
			if strings.EqualFold(inst.Name, name) {
				return true
			}
		}
		return false
	}
}

// ResolveGuestAndInstance looks up a guest and its Proxmox instance by
// identifier and an optional instance name filter.
//
// If instName is non-empty, only guests on that instance are considered.
// If multiple guests match, an error is returned hinting to use
// identifier@instance.
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

	instNames := make(map[int64]string, len(instances))
	for _, inst := range instances {
		instNames[inst.ID] = inst.Name
	}
	guest, err := resolveGuest(identifier, pool, instNames)
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
// Resolution order: numeric VMID → type+VMID (ct100, vm200) → name.
//
// It is deliberately unexported. Every caller must go through
// ResolveGuestAndInstance, which parses the "identifier@instance" form
// first -- a caller resolving a raw identifier would silently not support
// qualification, which is how `access grant --guest ct200@rome` came to be
// unable to name a guest on a colliding VMID at all.
//
// instNames is used to describe an ambiguity; see ambiguousError.
func resolveGuest(
	identifier string,
	guests []*models.Guest,
	instNames map[int64]string,
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
			return nil, ambiguousError(identifier, matches, instNames)
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
				fmt.Sprintf("%s%d", p, vmid), matches, instNames)
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
		return nil, ambiguousError(identifier, matches, instNames)
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
// It lists every alternative as a target the caller can type back
// verbatim, qualified by instance. The instance is what distinguishes
// them: listing bare ids for an ambiguous "ct100" would print "ct100,
// ct100" and say nothing. instNames may be nil, in which case only the
// bare ids are listed.
//
// There used to be a second, terser form for callers that could not
// express an instance prefix. Every caller can now -- a login name carries
// "ct100@rome" as readily as an argument does -- so one message serves
// both.
func ambiguousError(
	identifier string,
	matches []*models.Guest,
	instNames map[int64]string,
) error {
	hints := make([]string, 0, len(matches))
	for _, g := range matches {
		hints = append(hints, qualified(g, instNames))
	}
	return fmt.Errorf("%q matches %d guests: %s",
		identifier, len(matches), strings.Join(hints, ", "))
}

// qualified renders a guest as the "identifier@instance" target the user
// can type back verbatim. Without a known instance name it degrades to the
// bare identifier.
func qualified(g *models.Guest, instNames map[int64]string) string {
	id := fmt.Sprintf("%s%d", g.Type, g.ProxmoxID)
	if inst := instNames[g.InstanceID]; inst != "" {
		return id + "@" + inst
	}
	return id
}
