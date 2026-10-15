package session

import (
	"fmt"
	"sort"
	"strings"

	"proxpass/internal/models"
)

// guestRow is one line of the picker: either a guest or a Proxmox node.
//
// The display columns are precomputed rather than read back off the guest.
// That is what lets a node share this type at all -- a node has no vmid, no
// type and no status, so a renderer or a comparator that reached into
// .guest would have nothing to read and would have to branch. Here they
// read the same four strings whatever the row is, and only the two places
// that ACT on a selection care which kind it is.
type guestRow struct {
	// Exactly one of guest and inst is non-nil, and which one decides
	// what selecting the row does. Use isNode rather than testing them
	// directly.
	guest *models.Guest
	inst  *models.ProxmoxInstance

	// name is the NAME column: the guest's name, or the instance's.
	name string
	// instName is the HOST column. For a guest it is the instance
	// hosting it; for a node it is the instance itself, so that sorting
	// by host groups a node with the guests that live on it.
	instName string
	// id is the ID column: the type-qualified vmid for a guest, e.g.
	// "ct118", or nodeID for a node.
	id string
	// vmid is what sortByID orders on. Guests carry their Proxmox id;
	// nodes carry nodeSortID, which has no vmid to offer.
	vmid int
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

// newGuestRows builds the picker's rows in the default sort order, so the
// list has a stable order the user can learn. Discovery returns guests in
// whatever order the Proxmox API listed them, which changes between passes.
//
// The order here must match sortRows(rows, sortByName), since that is what
// the picker re-applies when a filter is cleared; sortRows is used directly
// rather than a second comparison function so the two cannot disagree.
func newGuestRows(guests []*GuestInfo) []guestRow {
	return newPickerRows(guests, nil)
}

// newPickerRows builds the rows for both kinds of target.
//
// Nodes and guests are listed together rather than in two sections: the
// user is choosing where to go, and a node is one of the places they can
// go. Keeping them in one list also means the filter and every sort apply
// to both without a special case.
func newPickerRows(guests []*GuestInfo, nodes []*models.ProxmoxInstance) []guestRow {
	rows := make([]guestRow, 0, len(guests)+len(nodes))
	for _, info := range guests {
		g := info.Guest
		id := fmt.Sprintf("%s%d", g.Type, g.ProxmoxID)
		inst := info.InstanceName
		rows = append(rows, guestRow{
			guest:    g,
			name:     g.Name,
			instName: inst,
			id:       id,
			vmid:     g.ProxmoxID,
			fields:   []string{g.Name, id, inst},
		})
	}
	for _, inst := range nodes {
		// The host column repeats the name deliberately: a node IS its
		// host, and leaving the column blank would make a node row look
		// like a guest whose instance had gone missing.
		rows = append(rows, guestRow{
			inst:     inst,
			name:     inst.Name,
			instName: inst.Name,
			id:       nodeID,
			vmid:     nodeSortID,
			// nodeID is included so that typing "node" filters the list
			// down to the nodes, which is the one query a mixed list
			// invites that a guest list never did.
			fields: []string{inst.Name, nodeID, inst.Name},
		})
	}
	sortRows(rows, sortByName)
	return rows
}

const (
	// nodeID fills the ID column for a node. A node has no vmid, and a
	// blank cell would read as missing data rather than as not
	// applicable.
	nodeID = "node"
	// nodeStatus fills the STATUS column. A node proxpass can list is
	// one it can reach, and there is no stopped state to report -- the
	// instance would simply be unreachable.
	nodeStatus = "-"
	// nodeSortID is where a node sorts in the ID column.
	//
	// Negative, so nodes come before every guest rather than being
	// scattered among vmids they have no relation to. Sorting by ID is
	// asking "which vmid", and a node is the answer to a different
	// question, so it belongs at one end; the top is where a short list
	// of nodes is easiest to find.
	nodeSortID = -1
)

// isNode reports whether this row is a Proxmox node rather than a guest.
func (r *guestRow) isNode() bool { return r.inst != nil }

// key identifies a row across a re-sort.
//
// Pointer identity cannot be used: a node row's guest pointer is nil, so
// every node would compare equal to every other and to "nothing selected".
// The kind prefix matters because a guest and a node may share a row id.
func (r *guestRow) key() string {
	if r.inst != nil {
		return fmt.Sprintf("n:%d", r.inst.ID)
	}
	if r.guest != nil {
		return fmt.Sprintf("g:%d", r.guest.ID)
	}
	return ""
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

// status is the STATUS column.
//
// Derived rather than stored, so a row cannot report a status its guest no
// longer has. The name and id columns are safe to precompute because they
// do not change while a picker is open; status does.
func (r *guestRow) status() string {
	if r.isNode() {
		return nodeStatus
	}
	return string(r.guest.Status)
}

// isRunning reports whether the row can actually be entered. Only a running
// guest has a console: pct enter and qm terminal both fail otherwise.
//
// A node is always enterable. It has no stopped state proxpass can see --
// an unreachable one simply fails to dial, which is reported then rather
// than guessed at here.
func (r *guestRow) isRunning() bool {
	if r.isNode() {
		return true
	}
	return r.guest.Status == models.StatusRunning
}
