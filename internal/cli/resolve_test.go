package cli_test

import (
	"errors"
	"strings"
	"testing"

	"proxpass/internal/cli"
	"proxpass/internal/models"
)

// guest builds a guest on the given instance.
func guest(instID int64, typ models.GuestType, vmid int, name string) *models.Guest {
	return &models.Guest{
		Type: typ, Name: name, ProxmoxID: vmid,
		InstanceID: instID, Status: models.StatusRunning,
	}
}

// twoInstances returns two instances and a pool where ct100 and the name
// "web" each exist on BOTH of them, so every identifier form is ambiguous.
func twoInstances() ([]*models.ProxmoxInstance, []*models.Guest) {
	insts := []*models.ProxmoxInstance{
		{ID: 1, Name: "rome"},
		{ID: 2, Name: "paris"},
	}
	return insts, []*models.Guest{
		guest(1, models.GuestTypeCT, 100, "web"),
		guest(2, models.GuestTypeCT, 100, "web"),
	}
}

// A VMID that exists on only one instance resolves without a qualifier, in
// all three identifier forms.
func TestResolveGuestUnambiguous(t *testing.T) {
	pool := []*models.Guest{
		guest(1, models.GuestTypeCT, 100, "web"),
		guest(1, models.GuestTypeVM, 200, "db"),
	}
	for _, ident := range []string{"100", "ct100", "web", "CT100", "Web"} {
		g, err := cli.ResolveGuest(ident, pool, true)
		if err != nil {
			t.Errorf("ResolveGuest(%q): %v", ident, err)
			continue
		}
		if g.ProxmoxID != 100 || g.Type != models.GuestTypeCT {
			t.Errorf("ResolveGuest(%q) = %s%d, want ct100", ident, g.Type, g.ProxmoxID)
		}
	}
}

// type+VMID must report an ambiguity rather than silently taking the first
// match. A VMID is unique per instance but not across them, so "ct100" can
// name two different machines; the old code returned whichever the query
// happened to yield first, connecting the user to an arbitrary one.
func TestResolveGuestReportsAmbiguousTypeVMID(t *testing.T) {
	_, pool := twoInstances()

	g, err := cli.ResolveGuest("ct100", pool, true)
	if err == nil {
		t.Fatalf("ct100 matches two guests but resolved to %s%d on instance %d",
			g.Type, g.ProxmoxID, g.InstanceID)
	}
	if errors.Is(err, cli.ErrGuestNotFound) {
		t.Errorf("an ambiguous identifier must not report not-found: %v", err)
	}
	if !strings.Contains(err.Error(), "ct100") {
		t.Errorf("error does not name the identifier: %v", err)
	}
}

// Every identifier form must behave the same way when ambiguous: the VMID
// and name tiers already did, and type+VMID now joins them.
func TestResolveGuestReportsAmbiguityForEveryForm(t *testing.T) {
	_, pool := twoInstances()
	for _, ident := range []string{"100", "ct100", "web"} {
		if _, err := cli.ResolveGuest(ident, pool, true); err == nil {
			t.Errorf("%q matches two guests but resolved without error", ident)
		}
	}
}

// An ambiguous identifier must say how to disambiguate, and the suggestion
// has to differ by caller: a caller that accepts "instance:identifier" is
// told to use it, while one that does not is given concrete ids.
func TestResolveGuestAmbiguityHints(t *testing.T) {
	_, pool := twoInstances()

	withPrefix, err := cli.ResolveGuest("web", pool, true)
	if err == nil {
		t.Fatalf("expected an ambiguity error, got %v", withPrefix)
	}
	if !strings.Contains(err.Error(), "instance:identifier") {
		t.Errorf("hintInstance error must suggest the instance prefix: %v", err)
	}

	_, err = cli.ResolveGuest("web", pool, false)
	if err == nil {
		t.Fatal("expected an ambiguity error")
	}
	if strings.Contains(err.Error(), "instance:identifier") {
		t.Errorf("without hintInstance the prefix must not be suggested: %v", err)
	}
	if !strings.Contains(err.Error(), "ct100") {
		t.Errorf("error must list the concrete ids: %v", err)
	}
}

// The alternatives listed for an ambiguity must be distinguishable from one
// another. "ct100" on two instances is the case that exposes this: listing
// bare ids would print "ct100, ct100", which tells the user nothing, so each
// one has to carry its instance name.
func TestResolveGuestAmbiguityListsDistinguishableAlternatives(t *testing.T) {
	insts, pool := twoInstances()

	_, _, err := cli.ResolveGuestAndInstanceHinted(
		"ct100", "", pool, insts, false /* hintInstance */)
	if err == nil {
		t.Fatal("expected an ambiguity error")
	}
	for _, want := range []string{"rome:ct100", "paris:ct100"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not list %q: %v", want, err)
		}
	}
	// The degenerate form the instance name exists to avoid.
	if strings.Contains(err.Error(), "ct100, ct100") {
		t.Errorf("alternatives are indistinguishable: %v", err)
	}
}

// An instance prefix resolves what is otherwise ambiguous.
func TestResolveGuestAndInstanceDisambiguatesByInstance(t *testing.T) {
	insts, pool := twoInstances()

	for _, tc := range []struct {
		target string
		want   int64
	}{
		{"rome:ct100", 1},
		{"paris:ct100", 2},
		{"rome:web", 1},
		{"paris:100", 2},
	} {
		instName, ident := cli.ParseGuestTarget(tc.target)
		g, inst, err := cli.ResolveGuestAndInstance(ident, instName, pool, insts)
		if err != nil {
			t.Errorf("%s: %v", tc.target, err)
			continue
		}
		if g.InstanceID != tc.want || inst.ID != tc.want {
			t.Errorf("%s resolved to instance %d, want %d",
				tc.target, g.InstanceID, tc.want)
		}
	}
}

// A miss must be distinguishable from an ambiguity, because callers treat
// them differently: a login name that names no guest falls back to the
// picker, while an ambiguous one has to be reported.
func TestResolveGuestNotFoundIsTyped(t *testing.T) {
	pool := []*models.Guest{guest(1, models.GuestTypeCT, 100, "web")}

	_, err := cli.ResolveGuest("nosuchguest", pool, true)
	if !errors.Is(err, cli.ErrGuestNotFound) {
		t.Errorf("a miss must wrap ErrGuestNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), "nosuchguest") {
		t.Errorf("error does not name the identifier: %v", err)
	}

	// An ambiguity must NOT satisfy errors.Is(ErrGuestNotFound): that would
	// make a caller fall back instead of reporting it.
	_, pool2 := twoInstances()
	_, err = cli.ResolveGuest("web", pool2, true)
	if errors.Is(err, cli.ErrGuestNotFound) {
		t.Errorf("an ambiguity must not be a not-found error: %v", err)
	}
}

// An unknown instance prefix is reported as such, not as a missing guest:
// "rome:ct100" with no instance "rome" is a different mistake.
func TestResolveGuestAndInstanceUnknownInstance(t *testing.T) {
	insts, pool := twoInstances()
	instName, ident := cli.ParseGuestTarget("berlin:ct100")
	if _, _, err := cli.ResolveGuestAndInstance(ident, instName, pool, insts); err == nil {
		t.Error("an unknown instance must be refused")
	} else if !strings.Contains(err.Error(), "berlin") {
		t.Errorf("error does not name the instance: %v", err)
	}
}
