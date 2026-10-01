package session

import (
	"fmt"
	"sort"
	"strings"

	"proxpass/internal/models"
)

// guestRow is a guest as the picker presents it: the guest itself plus the
// display and filter text derived from it.
type guestRow struct {
	guest    *models.Guest
	instName string
	// id is the type-qualified vmid, e.g. "ct118".
	id string
	// fields are matched against INDIVIDUALLY, best score wins.
	//
	// They must not be concatenated into one string: a subsequence would
	// then be allowed to span field boundaries, and "vpn" would match
	// "grt ... running pve" by taking the v from the vmid, the p from the
	// instance and the n from the status. That matched 20 of 50 guests and
	// made the filter useless.
	fields []string
	// score ranks this row within the current filter result.
	score int
}

// newGuestRows builds the picker's rows, sorted by name so the list has a
// stable order the user can learn. Discovery returns guests in whatever order
// the Proxmox API listed them, which changes between passes.
func newGuestRows(guests []*models.Guest, instNames map[int64]string) []guestRow {
	rows := make([]guestRow, 0, len(guests))
	for _, g := range guests {
		id := fmt.Sprintf("%s%d", g.Type, g.ProxmoxID)
		inst := instNames[g.InstanceID]
		rows = append(rows, guestRow{
			guest:    g,
			instName: inst,
			id:       id,
			fields:   []string{g.Name, id, inst},
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].guest.Name != rows[j].guest.Name {
			return rows[i].guest.Name < rows[j].guest.Name
		}
		return rows[i].id < rows[j].id
	})
	return rows
}

// filterRows returns the rows matching query, best match first.
//
// An empty query keeps the list in its stable alphabetical order rather than
// scoring everything equally, so the picker does not appear to shuffle itself
// the moment the filter is cleared.
func filterRows(rows []guestRow, query string) []guestRow {
	query = strings.TrimSpace(query)
	if query == "" {
		return rows
	}
	out := make([]guestRow, 0, len(rows))
	for _, r := range rows {
		best, matched := 0, false
		for i, field := range r.fields {
			score, ok := fuzzyScore(field, query)
			if !ok {
				continue
			}
			// The name is what users actually search by, so a hit there
			// outranks the same hit on the vmid or the instance name.
			score -= i * fieldRankPenalty
			if !matched || score > best {
				best, matched = score, true
			}
		}
		if !matched {
			continue
		}
		r.score = best
		out = append(out, r)
	}
	// A stable sort keeps the alphabetical order as the tie-breaker.
	sort.SliceStable(out, func(i, j int) bool { return out[i].score > out[j].score })
	return out
}

// fieldRankPenalty demotes a match found in a later (less important) field.
const fieldRankPenalty = 4

// isRunning reports whether the guest can actually be entered. Only a running
// guest has a console: pct enter and qm terminal both fail otherwise.
func (r guestRow) isRunning() bool {
	return r.guest.Status == models.StatusRunning
}
