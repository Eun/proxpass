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
	// sortUnset is the state a freshly opened picker is in. It is the zero
	// value, so a pickerState needs no explicit initialization.
	//
	// It exists because "opened sorted by name" and "cycled round to name"
	// have to behave differently on the next Tab: the first press starts the
	// walk at the head of the cycle, while a later one continues from where
	// it is. Without a distinct state the two are the same value and the
	// first Tab cannot be told from the third.
	//
	// It sorts and labels exactly as sortByName, so it is invisible to the
	// user -- the only thing it changes is where Tab goes next.
	sortUnset sortMode = iota
	sortByName
	sortByID
	sortByStatus
	sortByHost
	// sortModeCount bounds the mode range. Keep it last.
	sortModeCount
)

// sortCycle is the order Tab walks the columns in.
//
// Tab starts at id, then follows the header left to right: a user who has
// pressed the key once is being shown where it goes, and the columns they
// can see are easier to predict than an order that exists only in source.
// The picker still OPENS on name, which is what a human scanning a list of
// guests wants first; id is where the cycle begins, not where it rests.
//
// From a freshly opened picker the full sequence is therefore
//
//	name (open) → id → name → status → host → id → ...
//
// and every column is reachable.
var sortCycle = [...]sortMode{
	sortByID,
	sortByName,
	sortByStatus,
	sortByHost,
}

// cycleIndex is the position of m in sortCycle.
//
// sortUnset is deliberately absent from the cycle, and lands on the -1 that
// makes next() return the head: that is what sends the first Tab to id.
func (m sortMode) cycleIndex() int {
	for i, mode := range sortCycle {
		if mode == m {
			return i
		}
	}
	return -1
}

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
	case sortUnset, sortByName, sortModeCount:
		return defaultSortLabel
	default:
		return defaultSortLabel
	}
}

// defaultSortLabel is the label for sortByName, the mode the picker starts
// in.
const defaultSortLabel = "name"

// next returns the following mode in sortCycle, wrapping around.
func (m sortMode) next() sortMode {
	return sortCycle[(m.cycleIndex()+1)%len(sortCycle)]
}

// prev returns the preceding mode in sortCycle, wrapping around. It is the
// exact inverse of next for every mode in the cycle, so Shift+Tab undoes a
// Tab.
//
// From the opening state it goes to the cycle's LAST column rather than
// stepping back from name's position, mirroring next: both start the walk at
// an end of the cycle, forward from the head and backward from the tail.
func (m sortMode) prev() sortMode {
	if m == sortUnset {
		return sortCycle[len(sortCycle)-1]
	}
	return sortCycle[(m.cycleIndex()-1+len(sortCycle))%len(sortCycle)]
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
		case sortUnset, sortByName, sortModeCount:
			// Name is the primary key below. sortUnset is the freshly
			// opened picker, which is sorted by name.
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
