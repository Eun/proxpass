package api

// Tests for the activity-log handlers: ListActivity (admin-gated, paginated,
// newest-first), ReportSessionActivity (kind->EventID mapping, actor is the
// resolved identity, best-effort), and the record() no-op when disabled.

import (
	"context"
	"io"
	"log"
	"testing"
	"time"
)

// enableActivity turns on recording with a generous retention.
func enableActivity(h *SessionHandler) {
	h.WithActivityRetention(7 * 24 * time.Hour)
}

// TestListActivityPaginatesNewestFirst records several events (via admin
// mutations' recorder path, exercised directly through record) and lists them.
func TestListActivityNewestFirst(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	enableActivity(h)

	base := time.Now().Truncate(time.Second)
	for i := 0; i < 3; i++ {
		h.now = func() time.Time { return base.Add(time.Duration(i) * time.Second) }
		h.record(ctx, EventClientAdded, "admin", map[string]any{"n": float64(i)})
	}
	h.now = time.Now

	resp, err := h.ListActivity(ctx, ListActivityRequestObject{})
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	page, ok := resp.(ListActivity200JSONResponse)
	if !ok {
		t.Fatalf("expected 200, got %T", resp)
	}
	if page.Total != 3 || len(page.Entries) != 3 {
		t.Fatalf("total=%d entries=%d, want 3/3", page.Total, len(page.Entries))
	}
	if page.Entries[0].Params["n"] != float64(2) {
		t.Fatalf("not newest-first: first n=%v", page.Entries[0].Params["n"])
	}
	if page.Entries[0].EventID != EventClientAdded {
		t.Fatalf("event id = %q", page.Entries[0].EventID)
	}
}

// Pagination: limit + offset slice the newest-first list.
func TestListActivityPagination(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	enableActivity(h)
	base := time.Now().Truncate(time.Second)
	for i := 0; i < 5; i++ {
		h.now = func() time.Time { return base.Add(time.Duration(i) * time.Second) }
		h.record(ctx, EventClientAdded, "admin", map[string]any{"n": float64(i)})
	}
	h.now = time.Now

	limit, offset := 2, 2
	resp, err := h.ListActivity(ctx, ListActivityRequestObject{
		Params: ListActivityParams{Limit: &limit, Offset: &offset},
	})
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	page := resp.(ListActivity200JSONResponse)
	if page.Total != 5 || page.Limit != 2 || page.Offset != 2 || len(page.Entries) != 2 {
		t.Fatalf("page meta wrong: %+v", page)
	}
	// Newest-first full order is n=4,3,2,1,0; offset 2 -> n=2,1.
	if page.Entries[0].Params["n"] != float64(2) || page.Entries[1].Params["n"] != float64(1) {
		t.Fatalf("wrong page slice: %v, %v", page.Entries[0].Params["n"], page.Entries[1].Params["n"])
	}
}

// A client (non-admin) is refused with 403.
func TestListActivityRefusesAClient(t *testing.T) {
	h, repo, _ := newAdminHandler(t)
	enableActivity(h)
	resp, err := h.ListActivity(clientCtx(t, repo), ListActivityRequestObject{})
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if _, ok := resp.(ListActivity403JSONResponse); !ok {
		t.Fatalf("expected 403 for a client, got %T", resp)
	}
}

// When retention is 0, record() writes nothing (feature disabled).
func TestRecordDisabledWhenRetentionZero(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	// Do NOT enable activity (retention stays 0).
	h.record(ctx, EventClientAdded, "admin", map[string]any{"n": float64(1)})

	n, err := h.repo.CountActivity(ctx)
	if err != nil {
		t.Fatalf("CountActivity: %v", err)
	}
	if n != 0 {
		t.Fatalf("disabled recording still wrote %d rows", n)
	}
}

// ReportSessionActivity maps the kind to an EventID, records under the caller's
// identity, and returns 204.
func TestReportSessionActivityMapsKinds(t *testing.T) {
	cases := []struct {
		kind SessionActivityReportKind
		want EventID
	}{
		{SessionActivityKindConsole, EventSessionConsoleOpened},
		{SessionActivityKindCommand, EventSessionCommandRun},
		{SessionActivityKindSftp, EventSessionSftpOpened},
	}
	for _, c := range cases {
		h, _, ctx := newAdminHandler(t)
		enableActivity(h)
		body := SessionActivityReport{Kind: c.kind}
		resp, err := h.ReportSessionActivity(ctx, ReportSessionActivityRequestObject{Body: &body})
		if err != nil {
			t.Fatalf("ReportSessionActivity(%s): %v", c.kind, err)
		}
		if _, ok := resp.(ReportSessionActivity204Response); !ok {
			t.Fatalf("expected 204 for %s, got %T", c.kind, resp)
		}
		list, _ := h.repo.ListActivity(ctx, 10, 0)
		if len(list) != 1 || list[0].EventID != string(c.want) {
			t.Fatalf("kind %s recorded %v, want %s", c.kind, list, c.want)
		}
		// Actor is the resolved identity (AdminUser in this fixture).
		if list[0].Actor != AdminUser {
			t.Fatalf("actor = %q, want %q", list[0].Actor, AdminUser)
		}
	}
}

// A command report stores the command text (bounded).
func TestReportSessionActivityStoresCommand(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	enableActivity(h)
	cmd := "whoami"
	body := SessionActivityReport{Kind: SessionActivityKindCommand, Command: &cmd}
	if _, err := h.ReportSessionActivity(ctx, ReportSessionActivityRequestObject{Body: &body}); err != nil {
		t.Fatalf("ReportSessionActivity: %v", err)
	}
	list, _ := h.repo.ListActivity(ctx, 10, 0)
	if len(list) != 1 || list[0].Params["command"] != "whoami" {
		t.Fatalf("command not stored: %v", list)
	}
}

// A command report carries host+guest, which are stored as params so the log
// says WHERE the command ran. The command is stored VERBATIM (not quoted).
func TestReportSessionActivityStoresHostGuestAndRawCommand(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	enableActivity(h)
	// A command with characters strconv.Quote would escape: it must round-trip
	// unchanged, proving the value is not quoted anywhere in the path.
	cmd := `echo "hi"	world`
	host := "rome"
	guest := "ct100"
	body := SessionActivityReport{
		Kind: SessionActivityKindCommand, Command: &cmd, Host: &host, Guest: &guest,
	}
	if _, err := h.ReportSessionActivity(ctx, ReportSessionActivityRequestObject{Body: &body}); err != nil {
		t.Fatalf("ReportSessionActivity: %v", err)
	}
	list, _ := h.repo.ListActivity(ctx, 10, 0)
	if len(list) != 1 {
		t.Fatalf("want 1 row, got %d", len(list))
	}
	p := list[0].Params
	if p[paramCommand] != cmd {
		t.Errorf("command = %q, want verbatim %q (not quoted)", p[paramCommand], cmd)
	}
	if p[paramHost] != host {
		t.Errorf("host = %q, want %q", p[paramHost], host)
	}
	if p[paramGuest] != guest {
		t.Errorf("guest = %q, want %q", p[paramGuest], guest)
	}
}

// A node-targeted console carries only a host (no guest), and empty host/guest
// are omitted rather than stored as blank keys.
func TestReportSessionActivityOmitsEmptyHostGuest(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	enableActivity(h)
	host := "rome"
	empty := ""
	body := SessionActivityReport{Kind: SessionActivityKindConsole, Host: &host, Guest: &empty}
	if _, err := h.ReportSessionActivity(ctx, ReportSessionActivityRequestObject{Body: &body}); err != nil {
		t.Fatalf("ReportSessionActivity: %v", err)
	}
	list, _ := h.repo.ListActivity(ctx, 10, 0)
	if len(list) != 1 {
		t.Fatalf("want 1 row, got %d", len(list))
	}
	p := list[0].Params
	if p[paramHost] != host {
		t.Errorf("host = %q, want %q", p[paramHost], host)
	}
	if _, ok := p[paramGuest]; ok {
		t.Errorf("empty guest should be omitted, got %v", p[paramGuest])
	}
}

// An unknown kind is ignored (204, nothing recorded) rather than erroring.
func TestReportSessionActivityIgnoresUnknownKind(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	enableActivity(h)
	body := SessionActivityReport{Kind: SessionActivityReportKind("bogus")}
	resp, err := h.ReportSessionActivity(ctx, ReportSessionActivityRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("ReportSessionActivity: %v", err)
	}
	if _, ok := resp.(ReportSessionActivity204Response); !ok {
		t.Fatalf("expected 204, got %T", resp)
	}
	if n, _ := h.repo.CountActivity(ctx); n != 0 {
		t.Fatalf("unknown kind recorded %d rows", n)
	}
}

// boundedCommand caps overly long commands.
func TestBoundedCommand(t *testing.T) {
	long := make([]byte, maxActivityCommand+50)
	for i := range long {
		long[i] = 'x'
	}
	got := boundedCommand(string(long))
	if len([]rune(got)) != maxActivityCommand+1 { // +1 for the ellipsis rune
		t.Fatalf("bounded length = %d runes", len([]rune(got)))
	}
}

// TestNewActivityPrunerInterval verifies the pruner cadence is configurable:
// a positive interval is honored verbatim, and a non-positive one falls back to
// the default rather than producing a zero-duration ticker (which would panic).
func TestNewActivityPrunerInterval(t *testing.T) {
	_, repo, _ := newAdminHandler(t)
	logger := log.New(io.Discard, "", 0)

	for _, tc := range []struct {
		name     string
		interval time.Duration
		want     time.Duration
	}{
		{"configured value honored", 15 * time.Minute, 15 * time.Minute},
		{"zero falls back to default", 0, defaultActivityPruneInterval},
		{"negative falls back to default", -time.Second, defaultActivityPruneInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewActivityPruner(repo, time.Hour, tc.interval, logger)
			if p.interval != tc.want {
				t.Errorf("interval = %s, want %s", p.interval, tc.want)
			}
		})
	}
}

var _ = context.Background
