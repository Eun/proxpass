package session

import (
	"strings"
	"testing"

	"proxpass/internal/models"
)

func rows(t *testing.T, names ...string) []guestRow {
	t.Helper()
	guests := make([]*models.Guest, 0, len(names))
	for i, n := range names {
		guests = append(guests, &models.Guest{
			ID: int64(i + 1), Type: models.GuestTypeCT, Name: n,
			ProxmoxID: 100 + i, Status: models.StatusRunning, InstanceID: 1,
		})
	}
	return newGuestRows(guests, map[int64]string{1: "pve"})
}

func names(rs []guestRow) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.guest.Name)
	}
	return out
}

// The filter is the feature the plain numbered picker lost. It has to be a
// subsequence match, not a prefix or substring one, so that initials find a
// hyphenated name.
func TestFilterMatchesSubsequences(t *testing.T) {
	rs := rows(t, "mautrix-whatsapp", "mautrix-telegram", "jellyseerr", "unifi")

	for _, tc := range []struct {
		query string
		want  string
	}{
		{"mw", "mautrix-whatsapp"},
		{"whats", "mautrix-whatsapp"},
		{"jelly", "jellyseerr"},
		{"unf", "unifi"},
	} {
		got := filterRows(rs, tc.query)
		if len(got) == 0 {
			t.Errorf("query %q matched nothing", tc.query)
			continue
		}
		if got[0].guest.Name != tc.want {
			t.Errorf("query %q ranked %q first, want %q",
				tc.query, got[0].guest.Name, tc.want)
		}
	}
}

// A subsequence must not be allowed to span two fields: matching across the
// vmid, the instance name and the status made "vpn" match 20 of 50 guests,
// including ones with no v, p or n in their name at all.
func TestFilterDoesNotMatchAcrossFields(t *testing.T) {
	rs := rows(t, "grt", "vpn1", "homeassistant")
	got := filterRows(rs, "vpn")

	for _, r := range got {
		if r.guest.Name == "grt" {
			t.Fatalf("query %q matched %q by spanning fields; matches: %v",
				"vpn", "grt", names(got))
		}
	}
	if len(got) != 1 || got[0].guest.Name != "vpn1" {
		t.Errorf("got %v, want just vpn1", names(got))
	}
}

// A hit on the name outranks the same hit on the vmid or instance name,
// because the name is what users actually search by.
func TestFilterRanksNameMatchesFirst(t *testing.T) {
	const namedGuest = "ct100-app"
	rs := rows(t, "unrelated", "ct-named")
	// "ct1" matches the vmid of the first and the name of neither; make the
	// second one's NAME contain it so the ranking is observable.
	rs[1].guest.Name = namedGuest
	rs[1].fields = []string{namedGuest, rs[1].id, "pve"}

	got := filterRows(rs, "ct100")
	if len(got) == 0 {
		t.Fatal("no matches")
	}
	if got[0].guest.Name != namedGuest {
		t.Errorf("ranked %q first, want the name match %q",
			got[0].guest.Name, namedGuest)
	}
}

// Typing a vmid must find the guest: it is how the list is labeled.
func TestFilterMatchesTheVMID(t *testing.T) {
	rs := rows(t, "alpha", "beta")
	got := filterRows(rs, "ct101")
	if len(got) != 1 || got[0].guest.Name != "beta" {
		t.Errorf("filtering by vmid gave %v, want just beta", names(got))
	}
}

// A filter matching nothing must yield an empty list rather than everything,
// which would silently connect the user to the wrong guest on Enter.
func TestFilterWithNoMatchIsEmpty(t *testing.T) {
	if got := filterRows(rows(t, "alpha"), "zzzz"); len(got) != 0 {
		t.Errorf("got %v, want no matches", names(got))
	}
}

// An empty filter keeps the stable alphabetical order, so clearing the filter
// does not appear to shuffle the list.
func TestEmptyFilterKeepsAlphabeticalOrder(t *testing.T) {
	rs := rows(t, "zulu", "alpha", "mike")
	got := names(filterRows(rs, ""))
	want := []string{"alpha", "mike", "zulu"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

// Enter on a stopped guest must be refused: pct enter and qm terminal only
// work on a running guest, so connecting would fail after the picker exited.
func TestPickerRefusesAStoppedGuest(t *testing.T) {
	rs := rows(t, "alpha")
	rs[0].guest.Status = models.StatusStopped

	s := &pickerState{all: rs, shown: rs, width: 80, height: 24}
	if action := s.apply(key{kind: keyEnter}); action != actionNone {
		t.Errorf("action = %v, want the selection to be refused", action)
	}
	if !strings.Contains(s.notice, "stopped") {
		t.Errorf("notice = %q, want it to explain the guest is stopped", s.notice)
	}
}

// Typing must filter, and "q" must only quit while no filter is being typed —
// otherwise a guest whose name contains a q could never be searched for.
func TestQOnlyQuitsWhenNotFiltering(t *testing.T) {
	rs := rows(t, "quassel", "alpha")

	s := &pickerState{all: rs, shown: rs, width: 80, height: 24}
	if action := s.apply(key{kind: keyRune, r: 'q'}); action != actionQuit {
		t.Fatalf("bare q gave %v, want quit", action)
	}

	s = &pickerState{all: rs, shown: rs, width: 80, height: 24}
	s.apply(key{kind: keyRune, r: 'u'})
	if action := s.apply(key{kind: keyRune, r: 'a'}); action != actionNone {
		t.Fatalf("typing into the filter gave %v, want none", action)
	}
	if s.filter != "ua" {
		t.Fatalf("filter = %q, want %q", s.filter, "ua")
	}
	// With a filter active, q is text.
	if action := s.apply(key{kind: keyRune, r: 'q'}); action != actionQuit {
		_ = action
	} else {
		t.Error("q must be typed into an active filter, not quit")
	}
}

// Esc clears an active filter before it quits.
func TestEscClearsTheFilterFirst(t *testing.T) {
	rs := rows(t, "alpha")
	s := &pickerState{all: rs, shown: rs, width: 80, height: 24}
	s.apply(key{kind: keyRune, r: 'a'})

	if action := s.apply(key{kind: keyEsc}); action != actionNone {
		t.Errorf("esc with a filter gave %v, want none", action)
	}
	if s.filter != "" {
		t.Errorf("filter = %q, want it cleared", s.filter)
	}
	if action := s.apply(key{kind: keyEsc}); action != actionQuit {
		t.Errorf("esc with no filter gave %v, want quit", action)
	}
}

// The cursor must stay inside the list however far the user scrolls, and the
// viewport must follow it.
func TestCursorAndViewportStayInBounds(t *testing.T) {
	many := make([]string, 50)
	for i := range many {
		many[i] = string(rune('a'+i%26)) + "-guest"
	}
	rs := rows(t, many...)
	s := &pickerState{all: rs, shown: rs, width: 80, height: 24}

	s.move(-10)
	if s.cursor != 0 || s.offset != 0 {
		t.Errorf("scrolling up from the top gave cursor=%d offset=%d, want 0/0",
			s.cursor, s.offset)
	}

	s.move(1000)
	if s.cursor != len(rs)-1 {
		t.Errorf("cursor = %d, want the last row %d", s.cursor, len(rs)-1)
	}
	if s.cursor < s.offset || s.cursor >= s.offset+s.listRows() {
		t.Errorf("cursor %d is outside the viewport [%d,%d)",
			s.cursor, s.offset, s.offset+s.listRows())
	}
}

// Every rendered line must end with CRLF: the terminal is in raw mode, so a
// bare LF leaves the cursor in the same column and the frame staircases.
func TestRenderUsesCRLFOnly(t *testing.T) {
	rs := rows(t, "alpha", "beta")
	s := &pickerState{all: rs, shown: rs, width: 80, height: 24, user: "admin"}

	var b strings.Builder
	s.render(&b)
	out := b.String()

	if !strings.Contains(out, "\r\n") {
		t.Fatal("the frame contains no CRLF at all")
	}
	for i, r := range out {
		if r != '\n' {
			continue
		}
		if i == 0 || out[i-1] != '\r' {
			t.Fatalf("a bare LF at offset %d would staircase the output", i)
		}
	}
}

// The rendered frame must not exceed the terminal width, or the wrapping
// itself shifts every following line.
func TestRenderRespectsTheTerminalWidth(t *testing.T) {
	rs := rows(t, "a-guest-with-a-very-long-name-indeed-far-too-long")
	const width = 40
	s := &pickerState{all: rs, shown: rs, width: width, height: 24, user: "admin"}

	var b strings.Builder
	s.render(&b)
	for _, line := range strings.Split(b.String(), "\r\n") {
		if n := displayWidth(stripEscapes(line)); n > width {
			t.Errorf("line of %d columns exceeds the %d-column terminal: %q",
				n, width, line)
		}
	}
}

// stripEscapes removes the leading clear/home sequence and any styling so the
// printable width can be measured.
func stripEscapes(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case inEsc:
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
		case r == '\x1b':
			inEsc = true
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
