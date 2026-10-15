package session

import (
	"strings"
	"testing"

	"proxpass/internal/models"
)

const (
	pickNode  = "rome"
	pickGuest = "web"
	pickHost  = testHost
)

// Nodes share the picker with guests, so every column, sort and filter has
// to cope with a row that has no vmid, no type and no status.

// nodeRows builds rows for the named instances, with no guests.
func nodeRows(names ...string) []guestRow {
	insts := make([]*models.ProxmoxInstance, 0, len(names))
	for i, n := range names {
		insts = append(insts, &models.ProxmoxInstance{
			ID: int64(i + 1), Name: n, Node: n, SSHHost: n + ".example.com",
		})
	}
	return newPickerRows(nil, insts)
}

// mixedNodeRows is one guest and one node, for the cross-kind cases.
func mixedNodeRows(t *testing.T) []guestRow {
	t.Helper()
	guests := []*models.Guest{{
		ID: 1, Type: models.GuestTypeCT, Name: pickGuest,
		ProxmoxID: 100, Status: models.StatusRunning, InstanceID: 1,
	}}
	insts := []*models.ProxmoxInstance{{
		ID: 1, Name: pickNode, Node: pickNode, SSHHost: pickNode + ".example.com",
	}}
	return newPickerRows(guestInfos(guests, map[int64]string{1: pickNode}), insts)
}

func TestANodeRowFillsEveryColumn(t *testing.T) {
	rs := nodeRows(pickNode)
	if len(rs) != 1 {
		t.Fatalf("got %d rows, want 1", len(rs))
	}
	r := rs[0]
	if !r.isNode() {
		t.Error("isNode() = false for a row built from an instance")
	}
	if r.id != nodeID {
		t.Errorf("id = %q, want %q", r.id, nodeID)
	}
	if r.name != pickNode {
		t.Errorf("name = %q, want %q", r.name, pickNode)
	}
	if r.status() != nodeStatus {
		t.Errorf("status = %q, want %q", r.status(), nodeStatus)
	}
	// The host column must not be blank: an empty cell reads as a guest
	// whose instance went missing.
	if r.instName != pickNode {
		t.Errorf("instName = %q, want the instance's own name", r.instName)
	}
}

// A node is always connectable, so Enter must never be refused on one.
//
// isRunning gates Enter in both renderers and also picks the row color; a
// node has no stopped state, and the old implementation would have
// dereferenced a nil guest.
func TestEnterOnANodeIsNeverRefused(t *testing.T) {
	rs := nodeRows(pickNode)
	if !rs[0].isRunning() {
		t.Fatal("isRunning() = false for a node")
	}

	s := &pickerState{all: rs, shown: rs, width: 80, height: 24}
	if action := s.apply(key{kind: keyEnter}); action != actionSelect {
		t.Errorf("action = %v, want the node to be selected", action)
	}
	if s.notice != "" {
		t.Errorf("notice = %q, want none", s.notice)
	}
}

// Tab must keep the cursor on a selected NODE.
//
// This is the case pointer identity could not express: a node carries no
// guest, so comparing guest pointers made every node equal to every other
// and to "nothing selected", and Tab silently jumped to the top.
func TestSortKeepsTheSelectedNode(t *testing.T) {
	rs := newPickerRows(
		guestInfos([]*models.Guest{
			{ID: 1, Type: models.GuestTypeCT, Name: "aaa", ProxmoxID: 100,
				Status: models.StatusRunning, InstanceID: 1},
			{ID: 2, Type: models.GuestTypeCT, Name: "zzz", ProxmoxID: 300,
				Status: models.StatusRunning, InstanceID: 1},
		}, map[int64]string{1: pickHost}),
		[]*models.ProxmoxInstance{
			{ID: 1, Name: "mmm", Node: "mmm", SSHHost: "m.example.com"},
			{ID: 2, Name: "nnn", Node: "nnn", SSHHost: "n.example.com"},
		})

	s := &pickerState{all: rs, shown: rs, width: 80, height: 24}
	// The SECOND node, deliberately. A failing restore falls back to the
	// top of the list, and under the id sort the first node is already
	// there -- so selecting it could not tell a working restore from a
	// broken one.
	want, seen := "", 0
	for i, r := range s.shown {
		if !r.isNode() {
			continue
		}
		seen++
		if seen == 2 {
			s.cursor, want = i, r.key()
			break
		}
	}
	if want == "" {
		t.Fatal("fewer than two node rows in the fixture")
	}

	s.cycleSort(true)

	got := s.shown[s.cursor]
	if got.key() != want {
		t.Errorf("after Tab the cursor sits on %q (%s), want %q: the "+
			"selection jumped", got.key(), got.name, want)
	}
	// And it really did move, so the assertion above is not vacuous.
	if s.cursor == 0 {
		t.Error("the fixture left the selection at the top; it cannot " +
			"distinguish a restored cursor from a reset one")
	}
}

// Two nodes must not shuffle between sorts: the tie-breaker has to be a
// total order, and nodes agree on name-less keys like vmid and id.
func TestSortIsStableAcrossNodes(t *testing.T) {
	rs := nodeRows(pickNode, "paris", "berlin")
	for mode := sortUnset; mode < sortModeCount; mode++ {
		first := append([]guestRow(nil), rs...)
		sortRows(first, mode)
		second := append([]guestRow(nil), rs...)
		sortRows(second, mode)
		for i := range first {
			if first[i].key() != second[i].key() {
				t.Fatalf("mode %v is not deterministic at %d: %q vs %q",
					mode, i, first[i].key(), second[i].key())
			}
		}
	}
}

// Sorting by ID groups the nodes rather than scattering them among vmids
// they have no relation to.
func TestSortByIDGroupsNodesTogether(t *testing.T) {
	rs := mixedNodeRows(t)
	rs = append(rs, nodeRows("paris")...)
	sortRows(rs, sortByID)

	// Nodes first, then guests. The run of nodes must be contiguous.
	seenGuest := false
	for _, r := range rs {
		if r.isNode() {
			if seenGuest {
				t.Errorf("a node appears after a guest in the id sort: %v",
					names(rs))
				break
			}
			continue
		}
		seenGuest = true
	}
}

// A node ranks with the running guests, since it is always connectable.
func TestSortByStatusPutsNodesWithTheRunning(t *testing.T) {
	guests := []*models.Guest{{
		ID: 1, Type: models.GuestTypeCT, Name: "stopped-one",
		ProxmoxID: 100, Status: models.StatusStopped, InstanceID: 1,
	}}
	rs := newPickerRows(
		guestInfos(guests, map[int64]string{1: pickHost}),
		[]*models.ProxmoxInstance{{
			ID: 1, Name: pickNode, Node: pickNode, SSHHost: "r.example.com",
		}})
	sortRows(rs, sortByStatus)

	if !rs[0].isNode() {
		t.Errorf("a stopped guest outranked a node in the status sort: %v",
			names(rs))
	}
}

// Filtering reaches node rows, and "node" selects exactly them.
func TestFilterMatchesNodes(t *testing.T) {
	rs := mixedNodeRows(t)

	got := names(filterRows(rs, pickNode))
	if len(got) == 0 {
		t.Fatalf("filtering for the node name matched nothing: %v", names(rs))
	}

	// "node" is in every node row's fields and in no guest's.
	onlyNodes := filterRows(rs, nodeID)
	if len(onlyNodes) != 1 || !onlyNodes[0].isNode() {
		t.Errorf("filtering for %q gave %v, want just the node",
			nodeID, names(onlyNodes))
	}
}

// Both renderers must draw a node row without reaching into a nil guest.
func TestRenderersDrawNodeRows(t *testing.T) {
	rs := mixedNodeRows(t)

	t.Run("interactive", func(t *testing.T) {
		s := &pickerState{all: rs, shown: rs, width: 80, height: 24, user: "alice"}
		var b strings.Builder
		s.render(&b)
		out := b.String()
		for _, want := range []string{pickNode, nodeID, nodeStatus, pickGuest} {
			if !strings.Contains(out, want) {
				t.Errorf("rendered picker is missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("numbered", func(t *testing.T) {
		var b strings.Builder
		writeGuestTable(&b, rs)
		out := b.String()
		for _, want := range []string{pickNode, nodeID, pickGuest} {
			if !strings.Contains(out, want) {
				t.Errorf("rendered table is missing %q:\n%s", want, out)
			}
		}
	})
}

// Column widths must account for a node row's cells.
func TestColumnWidthsIncludeNodeRows(t *testing.T) {
	rs := nodeRows("a-very-long-instance-name")
	w := columnWidths(rs)
	if w.name < len("a-very-long-instance-name") {
		t.Errorf("name width = %d, too narrow for the node's name", w.name)
	}
	if w.id < len(nodeID) {
		t.Errorf("id width = %d, too narrow for %q", w.id, nodeID)
	}
}
