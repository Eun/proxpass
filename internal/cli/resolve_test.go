package cli_test

import (
	"errors"
	"strings"
	"testing"

	"proxpass/internal/cli"
	"proxpass/internal/models"
)

// Fixtures shared by the resolver tests.
const (
	instRome  = "rome"
	instParis = "paris"
	idCT100   = "ct100"
	// A guest name that itself contains "@", to prove the split takes the
	// LAST one.
	guestAtName  = "mail@corp"
	guestWebName = "web"
)

// guest builds a guest on the given instance.
func guest(instID int64, typ models.GuestType, vmid int, name string) *models.Guest {
	return &models.Guest{
		Type: typ, Name: name, ProxmoxID: vmid,
		InstanceID: instID, Status: models.StatusRunning,
	}
}

// twoInstances returns two instances and a pool where ct100 and the name
// guestWebName each exist on BOTH of them, so every identifier form is ambiguous.
func twoInstances() ([]*models.ProxmoxInstance, []*models.Guest) {
	insts := []*models.ProxmoxInstance{
		{ID: 1, Name: instRome},
		{ID: 2, Name: instParis},
	}
	return insts, []*models.Guest{
		guest(1, models.GuestTypeCT, 100, guestWebName),
		guest(2, models.GuestTypeCT, 100, guestWebName),
	}
}

// A VMID that exists on only one instance resolves without a qualifier, in
// all three identifier forms.
func TestResolveGuestUnambiguous(t *testing.T) {
	pool := []*models.Guest{
		guest(1, models.GuestTypeCT, 100, guestWebName),
		guest(1, models.GuestTypeVM, 200, "db"),
	}
	for _, ident := range []string{"100", idCT100, guestWebName, "CT100", "Web"} {
		g, err := cli.ResolveGuest(ident, pool)
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
// match. A VMID is unique per instance but not across them, so idCT100 can
// name two different machines; the old code returned whichever the query
// happened to yield first, connecting the user to an arbitrary one.
func TestResolveGuestReportsAmbiguousTypeVMID(t *testing.T) {
	_, pool := twoInstances()

	g, err := cli.ResolveGuest(idCT100, pool)
	if err == nil {
		t.Fatalf("ct100 matches two guests but resolved to %s%d on instance %d",
			g.Type, g.ProxmoxID, g.InstanceID)
	}
	if errors.Is(err, cli.ErrGuestNotFound) {
		t.Errorf("an ambiguous identifier must not report not-found: %v", err)
	}
	if !strings.Contains(err.Error(), idCT100) {
		t.Errorf("error does not name the identifier: %v", err)
	}
}

// Every identifier form must behave the same way when ambiguous: the VMID
// and name tiers already did, and type+VMID now joins them.
func TestResolveGuestReportsAmbiguityForEveryForm(t *testing.T) {
	_, pool := twoInstances()
	for _, ident := range []string{"100", idCT100, guestWebName} {
		if _, err := cli.ResolveGuest(ident, pool); err == nil {
			t.Errorf("%q matches two guests but resolved without error", ident)
		}
	}
}

// An ambiguous identifier must say how to disambiguate.
//
// There is only one message now: every caller can express
// "identifier@instance", so there is no longer a terser variant for
// callers that could not.
func TestResolveGuestAmbiguityHints(t *testing.T) {
	insts, pool := twoInstances()

	// Through ResolveGuest the instance names are not available, so the
	// best it can do is name the matches by id.
	_, err := cli.ResolveGuest(guestWebName, pool)
	if err == nil {
		t.Fatal("expected an ambiguity error")
	}
	if !strings.Contains(err.Error(), idCT100) {
		t.Errorf("error must list the matches: %v", err)
	}

	// Through ResolveGuestAndInstance the names ARE available, so each
	// alternative is a target that can be typed back verbatim.
	_, _, err = cli.ResolveGuestAndInstance(guestWebName, "", pool, insts)
	if err == nil {
		t.Fatal("expected an ambiguity error")
	}
	for _, want := range []string{idCT100 + "@" + instRome, idCT100 + "@" + instParis} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not offer %q: %v", want, err)
		}
	}
}

// The alternatives listed for an ambiguity must be distinguishable from one
// another. idCT100 on two instances is the case that exposes this: listing
// bare ids would print "ct100, ct100", which tells the user nothing, so each
// one has to carry its instance name.
func TestResolveGuestAmbiguityListsDistinguishableAlternatives(t *testing.T) {
	insts, pool := twoInstances()

	_, _, err := cli.ResolveGuestAndInstance(
		idCT100, "", pool, insts)
	if err == nil {
		t.Fatal("expected an ambiguity error")
	}
	for _, want := range []string{idCT100 + "@" + instRome, idCT100 + "@" + instParis} {
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
		{idCT100 + "@" + instRome, 1},
		{idCT100 + "@" + instParis, 2},
		{"web@" + instRome, 1},
		{"100@" + instParis, 2},
	} {
		instName, ident := cli.ParseGuestTarget(tc.target, cli.InstanceLookup(insts))
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
	pool := []*models.Guest{guest(1, models.GuestTypeCT, 100, guestWebName)}

	_, err := cli.ResolveGuest("nosuchguest", pool)
	if !errors.Is(err, cli.ErrGuestNotFound) {
		t.Errorf("a miss must wrap ErrGuestNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), "nosuchguest") {
		t.Errorf("error does not name the identifier: %v", err)
	}

	// An ambiguity must NOT satisfy errors.Is(ErrGuestNotFound): that would
	// make a caller fall back instead of reporting it.
	_, pool2 := twoInstances()
	_, err = cli.ResolveGuest(guestWebName, pool2)
	if errors.Is(err, cli.ErrGuestNotFound) {
		t.Errorf("an ambiguity must not be a not-found error: %v", err)
	}
}

// An unknown instance prefix is reported as such, not as a missing guest:
// instRome+":"+idCT100 with no instance instRome is a different mistake.
func TestResolveGuestAndInstanceUnknownInstance(t *testing.T) {
	insts, pool := twoInstances()
	instName, ident := cli.ParseGuestTarget("ct100@berlin", cli.InstanceLookup(insts))
	if _, _, err := cli.ResolveGuestAndInstance(ident, instName, pool, insts); err == nil {
		t.Error("an unknown instance must be refused")
	} else if !strings.Contains(err.Error(), "berlin") {
		t.Errorf("error does not name the instance: %v", err)
	}
}

// ParseGuestTarget splits on the LAST "@", and only when the suffix names a
// known instance.
//
// Both halves matter. Splitting on the last "@" lets a guest name keep an
// "@" of its own, since guest names come from Proxmox and are not
// validated; requiring a known instance stops a name like the client
// "tobias@corp" being read as a guest on an instance "corp".
func TestParseGuestTarget(t *testing.T) {
	insts := []*models.ProxmoxInstance{
		{ID: 1, Name: instRome},
		{ID: 2, Name: instParis},
	}
	known := cli.InstanceLookup(insts)

	tests := []struct {
		target   string
		wantInst string
		wantID   string
	}{
		{idCT100, "", idCT100},
		{idCT100 + "@" + instRome, instRome, idCT100},
		{"web@paris", instParis, guestWebName},
		// Case-insensitive, like instance resolution itself.
		{idCT100 + "@ROME", "ROME", idCT100},
		// Unknown suffix: the "@" belongs to the identifier.
		{"tobias@corp", "", "tobias@corp"},
		// A guest name containing "@", qualified: split on the LAST one.
		{guestAtName + "@" + instRome, instRome, guestAtName},
		// ... and unqualified: left whole.
		{guestAtName, "", guestAtName},
		// Degenerate forms are not splits.
		{"@" + instRome, "", "@" + instRome},
		{idCT100 + "@", "", idCT100 + "@"},
		{"", "", ""},
	}
	for _, tc := range tests {
		inst, id := cli.ParseGuestTarget(tc.target, known)
		if inst != tc.wantInst || id != tc.wantID {
			t.Errorf("ParseGuestTarget(%q) = (%q, %q), want (%q, %q)",
				tc.target, inst, id, tc.wantInst, tc.wantID)
		}
	}
}

// With no instance list, nothing is treated as a qualifier.
func TestParseGuestTargetWithoutInstances(t *testing.T) {
	inst, id := cli.ParseGuestTarget(idCT100+"@"+instRome, nil)
	if inst != "" || id != idCT100+"@"+instRome {
		t.Errorf("got (%q, %q), want (\"\", \"ct100@rome\")", inst, id)
	}
}

// The old "instance:identifier" form must no longer be honored, or two
// syntaxes would silently coexist.
func TestParseGuestTargetRejectsTheOldColonForm(t *testing.T) {
	insts := []*models.ProxmoxInstance{{ID: 1, Name: instRome}}
	inst, id := cli.ParseGuestTarget(instRome+":"+idCT100, cli.InstanceLookup(insts))
	if inst != "" {
		t.Errorf("the colon form was still parsed as an instance: %q", inst)
	}
	// A colon cannot appear in a login name anyway, so this can only come
	// from the CLI, where it must now fail to resolve rather than work.
	if id != instRome+":"+idCT100 {
		t.Errorf("identifier = %q, want the string left whole", id)
	}
}
