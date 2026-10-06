package session

import (
	"strings"
	"testing"

	"proxpass/internal/models"
)

// Fixture names, shared so the expected orders below read as data rather
// than as repeated string literals.
const (
	gAlpha = "alpha"
	gBravo = "bravo"
	gMike  = "mike"
	gZulu  = "zulu"
	gSame  = "same"

	testUser = "admin"
	testHost = "pve"
)

// mixedRows builds a set whose name, vmid, status and host orders all
// disagree, so a test can tell which column was actually sorted on. If they
// coincided, sorting by any of them would look identical and the test would
// pass against the wrong implementation.
//
//	name     vmid  status   host
//	zulu     101   running  alpha
//	alpha    300   stopped  zulu
//	mike     102   stopped  mike
//	bravo    200   running  bravo
func mixedRows(t *testing.T) []guestRow {
	t.Helper()
	specs := []struct {
		name   string
		vmid   int
		status models.Status
		host   string
	}{
		{gZulu, 101, models.StatusRunning, gAlpha},
		{gAlpha, 300, models.StatusStopped, gZulu},
		{gMike, 102, models.StatusStopped, gMike},
		{gBravo, 200, models.StatusRunning, gBravo},
	}
	guests := make([]*models.Guest, 0, len(specs))
	instNames := map[int64]string{}
	for i, s := range specs {
		instID := int64(i + 1)
		guests = append(guests, &models.Guest{
			ID: int64(i + 1), Type: models.GuestTypeCT, Name: s.name,
			ProxmoxID: s.vmid, Status: s.status, InstanceID: instID,
		})
		instNames[instID] = s.host
	}
	return newGuestRows(guestInfos(guests, instNames))
}

func TestSortRowsOrdersByTheChosenColumn(t *testing.T) {
	for _, tc := range []struct {
		mode sortMode
		want []string
	}{
		{sortByName, []string{gAlpha, gBravo, gMike, gZulu}},
		// By vmid ascending: 101, 102, 200, 300.
		{sortByID, []string{gZulu, gMike, gBravo, gAlpha}},
		// Running first, then each group by name.
		{sortByStatus, []string{gBravo, gZulu, gAlpha, gMike}},
		// Hosts are alpha, bravo, mike, zulu.
		{sortByHost, []string{gZulu, gBravo, gMike, gAlpha}},
	} {
		t.Run(tc.mode.label(), func(t *testing.T) {
			rs := mixedRows(t)
			sortRows(rs, tc.mode)
			got := names(rs)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("sort by %s = %v, want %v", tc.mode.label(), got, tc.want)
			}
		})
	}
}

// An id sort must be numeric. The displayed id is a string like "ct118", so
// sorting it as text puts ct99 after ct118.
func TestSortByIDIsNumericNotLexical(t *testing.T) {
	guests := []*models.Guest{
		{ID: 1, Type: models.GuestTypeCT, Name: "a", ProxmoxID: 118, Status: models.StatusRunning, InstanceID: 1},
		{ID: 2, Type: models.GuestTypeCT, Name: "b", ProxmoxID: 99, Status: models.StatusRunning, InstanceID: 1},
		{ID: 3, Type: models.GuestTypeCT, Name: "c", ProxmoxID: 1000, Status: models.StatusRunning, InstanceID: 1},
	}
	rs := newGuestRows(guestInfos(guests, map[int64]string{1: testHost}))
	sortRows(rs, sortByID)

	got := make([]int, 0, len(rs))
	for _, r := range rs {
		got = append(got, r.guest.ProxmoxID)
	}
	want := []int{99, 118, 1000}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("id order = %v, want %v (lexical would give 1000,118,99)", got, want)
		}
	}
}

// A status sort must put running guests first. Alphabetically "running"
// follows "stopped", which would bury every guest you can actually use.
func TestSortByStatusPutsRunningFirst(t *testing.T) {
	rs := mixedRows(t)
	sortRows(rs, sortByStatus)
	if !rs[0].isRunning() {
		t.Errorf("first row is %s, want a running guest", rs[0].guest.Status)
	}
	// Once a stopped guest appears, no running guest may follow it.
	seenStopped := false
	for _, r := range rs {
		if !r.isRunning() {
			seenStopped = true
			continue
		}
		if seenStopped {
			t.Error("a running guest sorted after a stopped one")
		}
	}
}

// Every mode must produce a total order, so rows that tie on the chosen
// column do not shuffle between repaints.
func TestSortRowsIsDeterministicOnTies(t *testing.T) {
	// Same status and host for everything: only the tie-breaker separates
	// these rows.
	guests := []*models.Guest{
		{ID: 1, Type: models.GuestTypeCT, Name: gSame, ProxmoxID: 102, Status: models.StatusRunning, InstanceID: 1},
		{ID: 2, Type: models.GuestTypeCT, Name: gSame, ProxmoxID: 101, Status: models.StatusRunning, InstanceID: 1},
		{ID: 3, Type: models.GuestTypeVM, Name: gSame, ProxmoxID: 101, Status: models.StatusRunning, InstanceID: 1},
	}
	for mode := sortByName; mode < sortModeCount; mode++ {
		first := newGuestRows(guestInfos(guests, map[int64]string{1: testHost}))
		sortRows(first, mode)
		for range 5 {
			again := newGuestRows(guestInfos(guests, map[int64]string{1: testHost}))
			sortRows(again, mode)
			for i := range first {
				if first[i].id != again[i].id {
					t.Fatalf("sort by %s is not deterministic: %v vs %v",
						mode.label(), ids(first), ids(again))
				}
			}
		}
	}
}

func ids(rs []guestRow) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.id)
	}
	return out
}

// Tab cycles forward through every mode and returns to the start; Shift+Tab
// goes the other way. A cycle that skipped or stuck on a mode would leave
// columns unreachable.
func TestSortModeCyclesThroughEveryColumn(t *testing.T) {
	seen := map[sortMode]bool{}
	m := sortByName
	for range int(sortModeCount) {
		if seen[m] {
			t.Fatalf("mode %s repeated before the cycle completed", m.label())
		}
		seen[m] = true
		m = m.next()
	}
	if m != sortByName {
		t.Errorf("cycling %d times ended on %s, want to wrap to name",
			sortModeCount, m.label())
	}
	if len(seen) != int(sortModeCount) {
		t.Errorf("cycle visited %d modes, want %d", len(seen), sortModeCount)
	}

	// Backward must be the exact inverse.
	for mode := sortByName; mode < sortModeCount; mode++ {
		if got := mode.next().prev(); got != mode {
			t.Errorf("%s.next().prev() = %s, want %s",
				mode.label(), got.label(), mode.label())
		}
	}
}

// Every mode needs a distinct label, or the status line cannot tell the user
// which one is active.
func TestSortModeLabelsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for mode := sortByName; mode < sortModeCount; mode++ {
		l := mode.label()
		if l == "" {
			t.Errorf("mode %d has an empty label", mode)
		}
		if seen[l] {
			t.Errorf("label %q is used by more than one mode", l)
		}
		seen[l] = true
	}
}

// --- key handling and filter interaction ---

// Tab must cycle the sort order, and must never be mistaken for filter text.
func TestTabCyclesSortAndShiftTabReverses(t *testing.T) {
	s := &pickerState{all: mixedRows(t), width: 80, height: 24}
	s.setFilter("")

	if s.sort != sortByName {
		t.Fatalf("default sort = %s, want name", s.sort.label())
	}
	if act := s.apply(key{kind: keyTab}); act != actionNone {
		t.Errorf("tab returned %v, want actionNone", act)
	}
	if s.sort != sortByID {
		t.Errorf("after tab, sort = %s, want id", s.sort.label())
	}
	if s.filter != "" {
		t.Errorf("tab leaked into the filter: %q", s.filter)
	}

	s.apply(key{kind: keyShiftTab})
	if s.sort != sortByName {
		t.Errorf("after shift+tab, sort = %s, want name", s.sort.label())
	}
	// Backwards past the first mode wraps to the last.
	s.apply(key{kind: keyShiftTab})
	if s.sort != sortByHost {
		t.Errorf("shift+tab from name = %s, want host", s.sort.label())
	}
}

// Tab must actually reorder the visible list, not just record a mode.
func TestTabReordersTheVisibleList(t *testing.T) {
	s := &pickerState{all: mixedRows(t), width: 80, height: 24}
	s.setFilter("")

	before := names(s.shown)
	s.apply(key{kind: keyTab}) // name -> id
	after := names(s.shown)

	if strings.Join(before, ",") == strings.Join(after, ",") {
		t.Errorf("list did not reorder: still %v", after)
	}
	want := []string{gZulu, gMike, gBravo, gAlpha} // vmid order
	if strings.Join(after, ",") != strings.Join(want, ",") {
		t.Errorf("after tab list = %v, want %v", after, want)
	}
}

// With a filter active the list stays ordered by relevance, because that is
// the point of filtering. Tab still records the choice for when the filter
// is cleared, and says so rather than appearing to do nothing.
func TestSortDoesNotDisturbFilterRelevance(t *testing.T) {
	s := &pickerState{all: mixedRows(t), width: 80, height: 24}
	// This filter must match EVERY row and rank them differently from the
	// sort column being switched to, or the assertion below cannot tell
	// relevance ordering apart from a re-sort. "0" matches the vmid of all
	// four and ranks them [alpha bravo mike zulu], which differs from the
	// id order [zulu mike bravo alpha] that Tab selects next. The vacuity
	// guard below enforces that rather than trusting this comment.
	s.setFilter("0")

	relevance := names(s.shown)
	s.apply(key{kind: keyTab})

	if got := names(s.shown); strings.Join(got, ",") != strings.Join(relevance, ",") {
		t.Errorf("filtering order changed on tab: %v became %v", relevance, got)
	}
	// Guard the guard: if relevance happened to equal the sort order, the
	// check above would pass even against a re-sort, so prove they differ.
	sorted := mixedRows(t)
	sortRows(sorted, s.sort)
	if strings.Join(relevance, ",") == strings.Join(names(sorted), ",") {
		t.Fatalf("test is vacuous: relevance order %v equals %s order",
			relevance, s.sort.label())
	}
	if s.notice == "" {
		t.Error("tab while filtering gave no feedback at all")
	}
	if !strings.Contains(s.notice, "filter") {
		t.Errorf("notice does not explain the filter interaction: %q", s.notice)
	}

	// Clearing the filter must then apply the mode that was chosen.
	s.setFilter("")
	want := []string{gZulu, gMike, gBravo, gAlpha} // id order
	if got := names(s.shown); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("after clearing the filter, list = %v, want %v (id order)", got, want)
	}
}

// setFilter itself must leave a filtered list in relevance order. This is
// separate from the test above because cycleSort returns early while
// filtering, so that path never reaches the branch being checked here --
// typing into the filter does.
func TestSetFilterKeepsRelevanceOrderRegardlessOfSortMode(t *testing.T) {
	for mode := sortByName; mode < sortModeCount; mode++ {
		t.Run(mode.label(), func(t *testing.T) {
			s := &pickerState{all: mixedRows(t), width: 80, height: 24}
			s.sort = mode

			// Relevance order for this filter, independent of any sort.
			want := names(filterRows(mixedRows(t), "0"))

			s.setFilter("0")
			got := names(s.shown)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("sort %s leaked into a filtered list: got %v, want %v",
					mode.label(), got, want)
			}
		})
	}
}

// Re-sorting should keep the highlighted guest selected: the usual reason to
// re-sort is to see where a guest sits under a different order.
func TestSortKeepsTheSelectedGuest(t *testing.T) {
	s := &pickerState{all: mixedRows(t), width: 80, height: 24}
	s.setFilter("")

	s.move(2) // highlight the third row
	selected := s.shown[s.cursor].guest.Name

	s.apply(key{kind: keyTab})
	if got := s.shown[s.cursor].guest.Name; got != selected {
		t.Errorf("selection moved from %q to %q across a re-sort", selected, got)
	}
}

// An empty list must not panic when the sort changes.
func TestSortWithNoGuests(t *testing.T) {
	s := &pickerState{all: nil, width: 80, height: 24}
	s.setFilter("")
	s.apply(key{kind: keyTab})
	if s.sort != sortByID {
		t.Errorf("sort = %s, want id", s.sort.label())
	}
}

// --- rendering ---

// The host is its own column now, and the active sort column is marked.
func TestRenderShowsHostColumnAndSortMarker(t *testing.T) {
	s := &pickerState{all: mixedRows(t), width: 100, height: 24, user: testUser}
	s.setFilter("")

	var b strings.Builder
	s.render(&b)
	out := b.String()

	for _, want := range []string{colID, colName, colStatus, colHost} {
		if !strings.Contains(out, want) {
			t.Errorf("header is missing the %s column: %q", want, out)
		}
	}
	// The default mode is name, so NAME carries the marker.
	if !strings.Contains(out, colName+sortMarker) {
		t.Errorf("NAME is not marked as the sort column: %q", out)
	}
	if strings.Contains(out, colID+sortMarker) {
		t.Errorf("ID is marked but is not the sort column: %q", out)
	}
	// Host values must appear in the rows, not just the header.
	if !strings.Contains(out, gAlpha) || !strings.Contains(out, gZulu) {
		t.Errorf("host values missing from the rows: %q", out)
	}
	if !strings.Contains(out, "sort: name") {
		t.Errorf("status line does not name the sort mode: %q", out)
	}
	if !strings.Contains(out, "tab sort") {
		t.Errorf("help line does not mention the tab hotkey: %q", out)
	}
}

// The marker must follow the mode.
func TestRenderMarkerFollowsTheSortMode(t *testing.T) {
	for _, tc := range []struct {
		mode   sortMode
		column string
	}{
		{sortByID, colID},
		{sortByName, colName},
		{sortByStatus, colStatus},
		{sortByHost, colHost},
	} {
		t.Run(tc.mode.label(), func(t *testing.T) {
			s := &pickerState{all: mixedRows(t), width: 100, height: 24, user: testUser}
			s.sort = tc.mode
			s.setFilter("")

			var b strings.Builder
			s.render(&b)
			if got := b.String(); !strings.Contains(got, tc.column+sortMarker) {
				t.Errorf("%s is not marked when sorting by %s", tc.column, tc.mode.label())
			}
		})
	}
}

// While filtering, no column may claim to be the sort column, because the
// list is ordered by relevance instead.
func TestRenderMarksNoColumnWhileFiltering(t *testing.T) {
	s := &pickerState{all: mixedRows(t), width: 100, height: 24, user: testUser}
	s.setFilter("a")

	var b strings.Builder
	s.render(&b)
	out := b.String()

	for _, c := range []string{colID, colName, colStatus, colHost} {
		if strings.Contains(out, c+sortMarker) {
			t.Errorf("%s is marked as the sort column while filtering: %q", c, out)
		}
	}
	if !strings.Contains(out, "best match") {
		t.Errorf("status line does not say the order is by relevance: %q", out)
	}
}
