package filter

import (
	"errors"
	"testing"
)

const statusRunning = "running"

type guest struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Type   string `json:"type"`
}

func guestFields() FieldSpecMap {
	return FieldSpecMap{
		"id":     {Column: "id"},
		"name":   {Column: "name"},
		"status": {Column: "status"},
		"type":   {Column: "type"},
	}
}

func sampleGuests() []guest {
	return []guest{
		{ID: 1, Name: "web-01", Status: statusRunning, Type: "vm"},
		{ID: 2, Name: "web-02", Status: statusRunning, Type: "vm"},
		{ID: 3, Name: "db-01", Status: "stopped", Type: "ct"},
	}
}

func TestMatchNoFilter(t *testing.T) {
	g := sampleGuests()
	out, err := Match(nil, g, guestFields())
	if err != nil || len(out) != 3 {
		t.Fatalf("nil filter: got %d rows, err %v; want 3", len(out), err)
	}
	empty := ""
	out, err = Match(&empty, g, guestFields())
	if err != nil || len(out) != 3 {
		t.Fatalf("empty filter: got %d rows, err %v; want 3", len(out), err)
	}
}

func TestMatchEq(t *testing.T) {
	out, err := Match(strp(`{"status":{"$eq":"running"}}`), sampleGuests(), guestFields())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d rows, want 2", len(out))
	}
	for _, g := range out {
		if g.Status != statusRunning {
			t.Errorf("row %+v is not running", g)
		}
	}
}

func TestMatchNumericEq(t *testing.T) {
	// A JSON number and a string both match an integer field.
	for _, raw := range []string{`{"id":{"$eq":2}}`, `{"id":{"$eq":"2"}}`} {
		out, err := Match(strp(raw), sampleGuests(), guestFields())
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if len(out) != 1 || out[0].ID != 2 {
			t.Errorf("%s: got %+v, want one row id=2", raw, out)
		}
	}
}

func TestMatchIContainsAndStartsWith(t *testing.T) {
	out, _ := Match(strp(`{"name":{"$icontains":"WEB"}}`), sampleGuests(), guestFields())
	if len(out) != 2 {
		t.Errorf("icontains WEB: got %d, want 2", len(out))
	}
	out, _ = Match(strp(`{"name":{"$startswith":"db"}}`), sampleGuests(), guestFields())
	if len(out) != 1 || out[0].Name != "db-01" {
		t.Errorf("startswith db: got %+v, want db-01", out)
	}
}

func TestMatchMultipleFieldsAnded(t *testing.T) {
	out, err := Match(strp(`{"type":{"$eq":"vm"},"status":{"$eq":"running"}}`), sampleGuests(), guestFields())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Errorf("got %d, want 2 (vm AND running)", len(out))
	}
}

func TestMatchOr(t *testing.T) {
	out, err := Match(strp(`{"id":{"$or":[{"$eq":"1"},{"$eq":"3"}]}}`), sampleGuests(), guestFields())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Errorf("got %d, want 2 (id 1 or 3)", len(out))
	}
}

func TestMatchNot(t *testing.T) {
	out, err := Match(strp(`{"status":{"$not":{"$eq":"running"}}}`), sampleGuests(), guestFields())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Status != "stopped" {
		t.Errorf("got %+v, want the one stopped row", out)
	}
}

func TestMatchUnknownField(t *testing.T) {
	_, err := Match(strp(`{"nope":{"$eq":"x"}}`), sampleGuests(), guestFields())
	if err == nil || !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("err = %v, want ErrInvalidFilter", err)
	}
}

func TestMatchMalformed(t *testing.T) {
	_, err := Match(strp(`{bad`), sampleGuests(), guestFields())
	if err == nil || !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("err = %v, want ErrInvalidFilter", err)
	}
}
