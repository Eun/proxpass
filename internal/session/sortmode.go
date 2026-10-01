package session

import (
	"sort"

	"proxpass/internal/models"
)

// sortMode is the column the picker's list is ordered by.
//
// Tab cycles forward through these and Shift+Tab backward. A plain letter
// could not be used: every printable rune the picker reads goes into the
// filter, so binding "s" would make it impossible to type a guest named
// "staging".
type sortMode int

const (
	sortByName sortMode = iota
	sortByID
	sortByStatus
	sortByHost
	// sortModeCount bounds the cycle. Keep it last.
	sortModeCount
)

// label names the mode in the status line.
//
// sortModeCount and any out-of-range value fall back to the default mode's
// label rather than reporting something that is not a column.
func (m sortMode) label() string {
	switch m {
	case sortByID:
		return "id"
	case sortByStatus:
		return "status"
	case sortByHost:
		return "host"
	case sortByName, sortModeCount:
		return defaultSortLabel
	default:
		return defaultSortLabel
	}
}

// defaultSortLabel is the label for sortByName, the mode the picker starts
// in.
const defaultSortLabel = "name"

// next returns the following mode, wrapping around.
func (m sortMode) next() sortMode {
	return (m + 1) % sortModeCount
}

// prev returns the preceding mode, wrapping around.
func (m sortMode) prev() sortMode {
	return (m - 1 + sortModeCount) % sortModeCount
}

// sortRows orders rows in place according to mode.
//
// Every comparison falls through to the name and then the numeric id, so the
// order is total: rows that tie on the chosen column keep a predictable
// order instead of shuffling between repaints.
func sortRows(rows []guestRow, mode sortMode) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch mode {
		case sortByID:
			// Numeric, not lexical. The display id is a string like
			// "ct118", so sorting it as text puts ct99 after ct118.
			if a.guest.ProxmoxID != b.guest.ProxmoxID {
				return a.guest.ProxmoxID < b.guest.ProxmoxID
			}
			// Same vmid on different instances is possible, and a CT and a
			// VM may share a number, so fall through to type then name.
			if a.guest.Type != b.guest.Type {
				return a.guest.Type < b.guest.Type
			}
		case sortByStatus:
			if a.guest.Status != b.guest.Status {
				// Running first: those are the ones that can be entered,
				// so they are what the user is usually looking for.
				return statusRank(a.guest.Status) < statusRank(b.guest.Status)
			}
		case sortByHost:
			if a.instName != b.instName {
				return a.instName < b.instName
			}
		case sortByName, sortModeCount:
			// Name is the primary key below.
		}
		return lessByNameThenID(a, b)
	})
}

// lessByNameThenID is the tie-breaker shared by every mode.
func lessByNameThenID(a, b guestRow) bool {
	if a.guest.Name != b.guest.Name {
		return a.guest.Name < b.guest.Name
	}
	if a.guest.ProxmoxID != b.guest.ProxmoxID {
		return a.guest.ProxmoxID < b.guest.ProxmoxID
	}
	return a.guest.Type < b.guest.Type
}

// statusRank orders statuses by usefulness rather than alphabetically, so a
// status sort puts the guests you can actually connect to at the top.
//
// Alphabetically "running" sorts after "stopped", which would bury every
// usable guest below the unusable ones.
func statusRank(s models.Status) int {
	if s == models.StatusRunning {
		return 0
	}
	return 1
}
