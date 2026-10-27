package db

import (
	"testing"
	"time"

	"proxpass/internal/models"
)

// addEvent is a small helper to append one event at a given time. Every test
// uses the same actor, so it is fixed here rather than taken as a parameter.
// It does not return the event: callers assert via ListActivity, not the
// inserted value.
func addEvent(t *testing.T, r Repository, eventID string, at time.Time, params map[string]any) {
	t.Helper()
	e := &models.ActivityEvent{EventID: eventID, Actor: testActor, OccurredAt: at, Params: params}
	if err := r.AddActivityEvent(t.Context(), e); err != nil {
		t.Fatalf("AddActivityEvent: %v", err)
	}
	if e.ID == 0 {
		t.Fatal("AddActivityEvent did not assign an id")
	}
}

// AddActivityEvent round-trips the event id, actor, time and params.
func TestActivityRoundTrips(t *testing.T) {
	r := newTestRepo(t)
	at := time.Now().Truncate(time.Second)
	addEvent(t, r, "instance.added", at, map[string]any{"name": testInstanceName, "id": float64(7)})

	list, err := r.ListActivity(t.Context(), 10, 0)
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d events, want 1", len(list))
	}
	e := list[0]
	if e.EventID != "instance.added" || e.Actor != testActor {
		t.Errorf("event = %+v", e)
	}
	if !e.OccurredAt.Equal(at.UTC()) {
		t.Errorf("occurred_at = %v, want %v", e.OccurredAt, at.UTC())
	}
	if e.Params["name"] != testInstanceName {
		t.Errorf("params = %v, want name=the instance", e.Params)
	}
}

// ListActivity returns newest-first and paginates by limit/offset.
func TestActivityNewestFirstAndPagination(t *testing.T) {
	r := newTestRepo(t)
	base := time.Now().Truncate(time.Second)
	// Insert oldest..newest; expect newest first out.
	for i := 0; i < 5; i++ {
		addEvent(t, r, "client.added", base.Add(time.Duration(i)*time.Second),
			map[string]any{"n": float64(i)})
	}

	if n, err := r.CountActivity(t.Context()); err != nil || n != 5 {
		t.Fatalf("CountActivity = %d, %v; want 5", n, err)
	}

	page1, err := r.ListActivity(t.Context(), 2, 0)
	if err != nil {
		t.Fatalf("ListActivity page1: %v", err)
	}
	if len(page1) != 2 || page1[0].Params["n"] != float64(4) || page1[1].Params["n"] != float64(3) {
		t.Fatalf("page1 not newest-first: %v", summarize(page1))
	}
	page2, err := r.ListActivity(t.Context(), 2, 2)
	if err != nil {
		t.Fatalf("ListActivity page2: %v", err)
	}
	if len(page2) != 2 || page2[0].Params["n"] != float64(2) || page2[1].Params["n"] != float64(1) {
		t.Fatalf("page2 wrong: %v", summarize(page2))
	}
	page3, err := r.ListActivity(t.Context(), 2, 4)
	if err != nil {
		t.Fatalf("ListActivity page3: %v", err)
	}
	if len(page3) != 1 || page3[0].Params["n"] != float64(0) {
		t.Fatalf("page3 wrong: %v", summarize(page3))
	}
}

func summarize(es []*models.ActivityEvent) []any {
	out := make([]any, len(es))
	for i, e := range es {
		out[i] = e.Params["n"]
	}
	return out
}

// DeleteActivityOlderThan prunes only events strictly older than the cutoff.
func TestActivityDeleteOlderThan(t *testing.T) {
	r := newTestRepo(t)
	now := time.Now().Truncate(time.Second)
	addEvent(t, r, "old.event", now.Add(-48*time.Hour), nil)
	addEvent(t, r, "mid.event", now.Add(-12*time.Hour), nil)
	addEvent(t, r, "new.event", now, nil)

	cutoff := now.Add(-24 * time.Hour)
	removed, err := r.DeleteActivityOlderThan(t.Context(), cutoff)
	if err != nil {
		t.Fatalf("DeleteActivityOlderThan: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed %d, want 1", removed)
	}
	list, _ := r.ListActivity(t.Context(), 10, 0)
	if len(list) != 2 {
		t.Fatalf("after prune %d events remain, want 2", len(list))
	}
	for _, e := range list {
		if e.EventID == "old.event" {
			t.Error("the old event was not pruned")
		}
	}
}

// An empty params map round-trips as a non-nil empty object, not null.
func TestActivityEmptyParams(t *testing.T) {
	r := newTestRepo(t)
	addEvent(t, r, "discovery.ran", time.Now(), nil)
	list, err := r.ListActivity(t.Context(), 10, 0)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListActivity = %d, %v", len(list), err)
	}
	if list[0].Params == nil {
		t.Error("params decoded as nil; want an empty object")
	}
}
