package session_test

import (
	"strings"
	"testing"

	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/session"
	"proxpass/internal/testenv"
)

const (
	// nodeSSHUser is the account proxpass uses on a Proxmox host.
	nodeSSHUser = "root"
	// aliceKey is the public key the test client authenticates with.
	aliceKey = "ssh-ed25519 AAAAalice alice"
)

// `ssh <instance-name>@proxpass' opens a shell on the Proxmox node.
//
// These pin the routing: which of node, guest and picker a login name
// reaches, and that a node the caller was not granted is reached by none of
// them.

// seedNodeInstance adds an instance configured for SSH, which is what a node
// shell needs: console transport decides how a GUEST console attaches and
// says nothing about reaching the node itself.
func seedNodeInstance(t *testing.T, repo db.Repository, name string) *models.ProxmoxInstance {
	t.Helper()
	inst := &models.ProxmoxInstance{
		Name: name, APIURL: "https://" + name + ":8006", Node: name,
		ConsoleTransport: models.ConsoleTransportTermProxy,
		SSHHost:          name + ".example.com", SSHPort: 22, SSHUser: nodeSSHUser,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance %q: %v", name, err)
	}
	return inst
}

// grantNode gives a client a node grant and returns the client.
func grantNode(t *testing.T, repo db.Repository, instID int64) *models.Client {
	t.Helper()
	client := &models.Client{
		Name: userAlice, PublicKeys: []string{aliceKey},
	}
	if err := repo.AddClient(t.Context(), client); err != nil {
		t.Fatalf("add client: %v", err)
	}
	stored, err := repo.GetClientByName(t.Context(), userAlice)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if err := repo.GrantClientInstanceAccess(
		t.Context(), stored.ID, []int64{instID}); err != nil {
		t.Fatalf("grant node: %v", err)
	}
	return stored
}

func TestLoginNameConnectsToTheNode(t *testing.T) {
	// Every spelling resolves, because names are matched without regard to
	// case -- the same rule the rest of proxpass applies.
	for _, login := range []string{instRome, "ROME", "Rome"} {
		t.Run(login, func(t *testing.T) {
			repo := newRepo(t)
			inst := seedNodeInstance(t, repo, instRome)
			client := grantNode(t, repo, inst.ID)

			proxier := &testenv.MockProxier{}
			tb := newTerminal("")
			d := newDeps(repo, tb, proxier)
			d.LoginName = login
			d.IdentityName = userAlice
			d.ClientID = client.ID

			if code := session.Run(t.Context(), d); code != 0 {
				t.Fatalf("exit = %d, want 0 (err: %q)", code, tb.errb.String())
			}
			got := proxier.SessionsSnapshot()
			if len(got) != 1 {
				t.Fatalf("got %d sessions, want 1: %+v", len(got), got)
			}
			if !got[0].IsNode {
				t.Errorf("connected to a guest console, not the node: %+v", got[0])
			}
			if got[0].InstanceName != instRome {
				t.Errorf("instance = %q, want %q", got[0].InstanceName, instRome)
			}
		})
	}
}

// A node the caller was not granted is not reachable, and is indistinguishable
// from one that does not exist.
//
// The whole point of scoping resolution to accessible instances: were an
// ungranted node to resolve and then be refused, the difference between
// "access denied" and the picker would map out the cluster.
func TestAnUngrantedNodeIsIndistinguishableFromAMissingOne(t *testing.T) {
	repo := newRepo(t)
	inst := seedNodeInstance(t, repo, instSecret)
	// A guest the client CAN reach, so the picker has something to show
	// and the two runs below differ only in the login name.
	seedGuestOn(t, repo, inst.ID, models.GuestTypeCT, 100, guestMine)
	client := &models.Client{
		Name: userAlice, PublicKeys: []string{aliceKey},
	}
	if err := repo.AddClient(t.Context(), client); err != nil {
		t.Fatalf("add client: %v", err)
	}
	stored, err := repo.GetClientByName(t.Context(), userAlice)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	guests, err := repo.ListGuests(t.Context())
	if err != nil {
		t.Fatalf("list guests: %v", err)
	}
	if err := repo.GrantClientAccess(t.Context(), stored.ID, []int64{guests[0].ID}); err != nil {
		t.Fatalf("grant guest: %v", err)
	}

	run := func(login string) (string, int) {
		t.Helper()
		proxier := &testenv.MockProxier{}
		// "q" quits the picker, so a run that reaches it ends cleanly.
		tb := newTerminal("q\n")
		d := newDeps(repo, tb, proxier)
		d.LoginName = login
		d.IdentityName = userAlice
		d.ClientID = stored.ID
		code := session.Run(t.Context(), d)
		if n := len(proxier.SessionsSnapshot()); n != 0 {
			t.Fatalf("%s: connected %d times; an ungranted node must not be reached", login, n)
		}
		return tb.out.String() + tb.errb.String(), code
	}

	existing, existingCode := run(instSecret)
	missing, missingCode := run("nosuchnode")

	if existing != missing {
		t.Errorf("an ungranted node that EXISTS answered differently from one "+
			"that does not:\n existing: %q\n missing:  %q", existing, missing)
	}
	if existingCode != missingCode {
		t.Errorf("exit codes differ: %d vs %d", existingCode, missingCode)
	}
	if strings.Contains(existing, "access denied") {
		t.Errorf("an ungranted node reported access denied, which discloses it: %q", existing)
	}
}

// When a node and a guest share a name, the node wins.
//
// Deliberate and asymmetric: a shadowed guest is still reachable as
// "<guest>@<instance>", while a node has no qualified form, so resolving the
// guest first would make the node unreachable entirely.
func TestANodeNameBeatsAGuestOfTheSameName(t *testing.T) {
	repo := newRepo(t)
	inst := seedNodeInstance(t, repo, instRome)
	// A guest called "rome" on the very same instance.
	seedGuestOn(t, repo, inst.ID, models.GuestTypeCT, 100, instRome)

	client := grantNode(t, repo, inst.ID)
	guests, err := repo.ListGuests(t.Context())
	if err != nil {
		t.Fatalf("list guests: %v", err)
	}
	// Grant the guest too, so the guest branch would succeed if reached:
	// the test must prove ordering, not that the guest was unreachable.
	if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{guests[0].ID}); err != nil {
		t.Fatalf("grant guest: %v", err)
	}

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	d.LoginName = instRome
	d.IdentityName = userAlice
	d.ClientID = client.ID

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit = %d, want 0 (err: %q)", code, tb.errb.String())
	}
	got := proxier.SessionsSnapshot()
	if len(got) != 1 {
		t.Fatalf("got %d sessions, want 1: %+v", len(got), got)
	}
	if !got[0].IsNode {
		t.Errorf("the guest won over the node; the node would then be "+
			"unreachable, having no qualified form: %+v", got[0])
	}
}

// The shadowed guest is still reachable by its qualified name, which is what
// makes the rule above acceptable.
func TestAGuestShadowedByANodeIsStillReachableQualified(t *testing.T) {
	repo := newRepo(t)
	inst := seedNodeInstance(t, repo, instRome)
	seedGuestOn(t, repo, inst.ID, models.GuestTypeCT, 100, instRome)

	client := grantNode(t, repo, inst.ID)
	guests, err := repo.ListGuests(t.Context())
	if err != nil {
		t.Fatalf("list guests: %v", err)
	}
	if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{guests[0].ID}); err != nil {
		t.Fatalf("grant guest: %v", err)
	}

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	d.LoginName = instRome + "@" + instRome // guest "rome" on instance "rome"
	d.IdentityName = userAlice
	d.ClientID = client.ID

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit = %d, want 0 (err: %q)", code, tb.errb.String())
	}
	got := proxier.SessionsSnapshot()
	if len(got) != 1 {
		t.Fatalf("got %d sessions, want 1: %+v", len(got), got)
	}
	if got[0].IsNode {
		t.Errorf("the qualified form reached the node; the shadowed guest "+
			"would then have no way to be named: %+v", got[0])
	}
	if got[0].GuestName != instRome {
		t.Errorf("guest = %q, want %q", got[0].GuestName, instRome)
	}
}

// A command runs ON the node: "ssh rome@host uptime".
//
// MockProxier cannot serve this -- a command does not go through Proxier at
// all -- so this asserts the routing decision rather than the execution:
// the command must NOT be parsed as a proxpass CLI command, which is what
// used to happen and produced a confusing usage error.
func TestACommandOnANodeIsNotTreatedAsAProxpassCommand(t *testing.T) {
	repo := newRepo(t)
	inst := seedNodeInstance(t, repo, instRome)
	client := grantNode(t, repo, inst.ID)

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	d.LoginName = instRome
	d.IdentityName = userAlice
	d.ClientID = client.ID
	d.Command = "uptime"

	// The dial fails: the fixture host does not exist. That is the point --
	// reaching a dial attempt proves the command was routed to the node.
	code := session.Run(t.Context(), d)
	if code == 0 {
		t.Fatalf("expected the dial to fail against a fixture host, got 0")
	}
	combined := tb.out.String() + tb.errb.String()
	for _, cliNoise := range []string{"usage", "Usage", "unknown command", "flag provided"} {
		if strings.Contains(combined, cliNoise) {
			t.Errorf("the command was parsed as a proxpass CLI command (%q): %q",
				cliNoise, combined)
		}
	}
	if !strings.Contains(combined, "cannot reach") {
		t.Errorf("expected a dial failure naming the node, got: %q", combined)
	}
}

// A command under a name that is neither node nor guest still reaches the
// proxpass CLI. The node check must not swallow ordinary CLI use.
func TestACommandUnderANonNodeNameStillReachesTheCLI(t *testing.T) {
	repo := newRepo(t)
	seedNodeInstance(t, repo, instRome)
	client := grantNode(t, repo, 0) // granted nothing reachable

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	d.LoginName = "nobody-in-particular"
	d.IdentityName = userAlice
	d.ClientID = client.ID
	d.Command = cmdGuestLs

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit = %d, want 0: the proxpass CLI should have run (err: %q)",
			code, tb.errb.String())
	}
}

// The administrator's name keeps meaning "browse", even when an instance
// bears it. Otherwise adding an instance called "admin" would take the CLI
// away from the administrator.
func TestAnInstanceNamedAdminDoesNotStealTheAdminLogin(t *testing.T) {
	repo := newRepo(t)
	seedNodeInstance(t, repo, "admin")
	// A guest so the picker has something to show rather than erroring.
	instances, err := repo.ListProxmoxInstances(t.Context())
	if err != nil {
		t.Fatalf("list instances: %v", err)
	}
	seedGuestOn(t, repo, instances[0].ID, models.GuestTypeCT, 100, guestWeb)

	proxier := &testenv.MockProxier{}
	tb := newTerminal("q\n")
	tb.term.Raw = true
	d := newDeps(repo, tb, proxier)
	d.LoginName = "admin"
	d.IsAdmin = true

	session.Run(t.Context(), d)

	for _, s := range proxier.SessionsSnapshot() {
		if s.IsNode {
			t.Errorf("the reserved admin name opened a node shell: %+v", s)
		}
	}
}

// ...and keeps the CLI too, which is the case the picker test above misses.
//
// connectByLoginName checks the reserved name before anything else, so the
// no-command path is protected twice over. The COMMAND path has no such
// outer check: namesANode is the first thing Run consults, so its own
// reserved-name guard is the only thing standing between an instance called
// "admin" and the administrator losing `ssh admin@host guest ls' to an SSH
// attempt against that node.
func TestAnInstanceNamedAdminDoesNotStealTheAdminCLI(t *testing.T) {
	repo := newRepo(t)
	seedNodeInstance(t, repo, "admin")
	instances, err := repo.ListProxmoxInstances(t.Context())
	if err != nil {
		t.Fatalf("list instances: %v", err)
	}
	seedGuestOn(t, repo, instances[0].ID, models.GuestTypeCT, 100, guestWeb)

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	d.LoginName = "admin"
	d.IsAdmin = true
	d.Command = cmdGuestLs

	code := session.Run(t.Context(), d)
	out := tb.out.String() + tb.errb.String()
	if code != 0 {
		t.Fatalf("exit = %d, want 0: the admin CLI must still run: %q", code, out)
	}
	if !strings.Contains(out, guestWeb) {
		t.Errorf("`%s' did not list %q; the admin lost the CLI to a node "+
			"called \"admin\": %q", cmdGuestLs, guestWeb, out)
	}
}

// The qualified "x@rome" form is never a node.
//
// Two reasons it must not be: it is the guest-on-instance form and belongs
// to guest resolution, and a client may legitimately be called
// "tobias@corp", which must not be read as a node called "corp".
func TestAQualifiedNameIsNeverANode(t *testing.T) {
	repo := newRepo(t)
	inst := seedNodeInstance(t, repo, instRome)
	seedGuestOn(t, repo, inst.ID, models.GuestTypeCT, 100, guestWeb)
	client := grantNode(t, repo, inst.ID)
	guests, err := repo.ListGuests(t.Context())
	if err != nil {
		t.Fatalf("list guests: %v", err)
	}
	if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{guests[0].ID}); err != nil {
		t.Fatalf("grant guest: %v", err)
	}

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	// The guest "web" on instance "rome" -- NOT the node "rome".
	d.LoginName = guestWeb + "@" + instRome
	d.IdentityName = userAlice
	d.ClientID = client.ID

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit = %d, want 0 (err: %q)", code, tb.errb.String())
	}
	got := proxier.SessionsSnapshot()
	if len(got) != 1 {
		t.Fatalf("got %d sessions, want 1: %+v", len(got), got)
	}
	if got[0].IsNode {
		t.Errorf("%q reached the node; the qualified form names a GUEST on "+
			"an instance: %+v", d.LoginName, got[0])
	}
	if got[0].GuestName != guestWeb {
		t.Errorf("guest = %q, want %q", got[0].GuestName, guestWeb)
	}
}

// A revoked node is no longer reachable by name.
//
// This exercises the SCOPING rather than the re-check inside
// connectNodeChecked: once the grant is gone the name stops resolving as a
// node at all, so the request never reaches the connect path. That is the
// intended arrangement -- the re-check there is defense in depth, kept so
// that widening the scoping alone cannot open a hole -- and it is why this
// ends at the picker rather than at "access denied".
func TestARevokedNodeIsNoLongerReachableByName(t *testing.T) {
	repo := newRepo(t)
	inst := seedNodeInstance(t, repo, instRome)
	client := grantNode(t, repo, inst.ID)
	if err := repo.RevokeClientInstanceAccess(t.Context(), client.ID, inst.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	proxier := &testenv.MockProxier{}
	tb := newTerminal("q\n")
	d := newDeps(repo, tb, proxier)
	d.LoginName = instRome
	d.IdentityName = userAlice
	d.ClientID = client.ID

	session.Run(t.Context(), d)

	for _, s := range proxier.SessionsSnapshot() {
		if s.IsNode {
			t.Errorf("attached to a node after the grant was revoked: %+v", s)
		}
	}
}

// An instance whose NAME contains "@" must not shadow a guest.
//
// Instance names are not validated, so "web@rome" is a name an
// administrator can actually create -- confirmed against the repository,
// not assumed. Without the "@" guard in namesANode such an instance would
// swallow `ssh web@rome@host', which addresses the guest "web" on the
// instance "rome", and the guest would become unreachable.
func TestAnInstanceNamedWithAnAtSignDoesNotShadowAGuest(t *testing.T) {
	repo := newRepo(t)
	rome := seedNodeInstance(t, repo, instRome)
	seedGuestOn(t, repo, rome.ID, models.GuestTypeCT, 100, guestWeb)

	// The trap: an instance literally called "web@rome".
	trap := &models.ProxmoxInstance{
		Name: guestWeb + "@" + instRome, APIURL: "https://trap:8006", Node: "trap",
		ConsoleTransport: models.ConsoleTransportTermProxy,
		SSHHost:          "trap.example.com", SSHPort: 22, SSHUser: nodeSSHUser,
	}
	if err := repo.AddProxmoxInstance(t.Context(), trap); err != nil {
		t.Fatalf("add trap instance: %v", err)
	}

	client := grantNode(t, repo, trap.ID)
	guests, err := repo.ListGuests(t.Context())
	if err != nil {
		t.Fatalf("list guests: %v", err)
	}
	if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{guests[0].ID}); err != nil {
		t.Fatalf("grant guest: %v", err)
	}

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	d.LoginName = guestWeb + "@" + instRome
	d.IdentityName = userAlice
	d.ClientID = client.ID

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit = %d, want 0 (err: %q)", code, tb.errb.String())
	}
	got := proxier.SessionsSnapshot()
	if len(got) != 1 {
		t.Fatalf("got %d sessions, want 1: %+v", len(got), got)
	}
	if got[0].IsNode {
		t.Errorf("an instance named %q swallowed the guest form: %+v",
			trap.Name, got[0])
	}
	if got[0].GuestName != guestWeb || got[0].InstanceName != instRome {
		t.Errorf("reached %s on %s, want %s on %s",
			got[0].GuestName, got[0].InstanceName, guestWeb, instRome)
	}
}

// THE gap Phase 5 closes: a client granted only a node can browse.
//
// Before this the picker listed guests only, so such a client ran `ssh
// alice@host', was told "no guests available" and got exit 1 -- with no way
// to discover the node it had in fact been granted.
func TestAClientGrantedOnlyANodeCanBrowse(t *testing.T) {
	repo := newRepo(t)
	inst := seedNodeInstance(t, repo, instRome)
	client := grantNode(t, repo, inst.ID)

	proxier := &testenv.MockProxier{}
	// "1" selects the only row; the numbered fallback needs no raw mode.
	tb := newTerminal("1\n")
	d := newDeps(repo, tb, proxier)
	d.LoginName = userAlice
	d.IdentityName = userAlice
	d.ClientID = client.ID

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit = %d, want 0 (err: %q)", code, tb.errb.String())
	}
	if strings.Contains(tb.errb.String(), "no guests available") {
		t.Errorf("a client with a node grant was told there is nothing: %q",
			tb.errb.String())
	}
	got := proxier.SessionsSnapshot()
	if len(got) != 1 {
		t.Fatalf("got %d sessions, want 1: %+v", len(got), got)
	}
	if !got[0].IsNode || got[0].InstanceName != instRome {
		t.Errorf("picked %+v, want the node %q", got[0], instRome)
	}
}

// A client granted nothing at all still gets a refusal, not an empty list.
func TestAClientGrantedNothingIsStillRefused(t *testing.T) {
	repo := newRepo(t)
	seedNodeInstance(t, repo, instRome)
	client := &models.Client{Name: userAlice, PublicKeys: []string{aliceKey}}
	if err := repo.AddClient(t.Context(), client); err != nil {
		t.Fatalf("add client: %v", err)
	}
	stored, err := repo.GetClientByName(t.Context(), userAlice)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	d.LoginName = userAlice
	d.IdentityName = userAlice
	d.ClientID = stored.ID

	if code := session.Run(t.Context(), d); code == 0 {
		t.Errorf("exit = 0; a client granted nothing should be refused")
	}
	if len(proxier.SessionsSnapshot()) != 0 {
		t.Error("a client granted nothing connected to something")
	}
}

// An instance with no ssh-host is not offered in the picker.
//
// It cannot be opened -- a node is reached only over SSH -- so listing it
// would offer a choice that always fails. The caller is still told why if
// they name it directly; see the API's ConnectSessionNode.
func TestAnInstanceWithNoSSHHostIsNotListed(t *testing.T) {
	repo := newRepo(t)
	// Deliberately not seedNodeInstance: no ssh_host.
	inst := &models.ProxmoxInstance{
		Name: instRome, APIURL: romeAPIURL, Node: instRome,
		ConsoleTransport: models.ConsoleTransportTermProxy,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	client := grantNode(t, repo, inst.ID)

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	d.LoginName = userAlice
	d.IdentityName = userAlice
	d.ClientID = client.ID

	// Nothing reachable, so this refuses rather than offering a row that
	// cannot be connected to.
	if code := session.Run(t.Context(), d); code == 0 {
		t.Errorf("exit = 0; an unreachable node must not be offered: out=%q",
			tb.out.String())
	}
	if strings.Contains(tb.out.String(), instRome) {
		t.Errorf("the picker listed an instance with no ssh-host: %q",
			tb.out.String())
	}
}
