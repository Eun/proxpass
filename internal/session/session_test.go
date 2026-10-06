package session_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	ucli "github.com/urfave/cli/v3"

	"proxpass/internal/console"
	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/session"
	"proxpass/internal/testenv"
)

const (
	userAlice = "alice"
	// userAlias is a login name that is not a client, so it resolves to the
	// administrator rather than to an account of its own.
	userAlias  = "tobias"
	guestCT100 = "ct100"
	// guestWeb is the name of the guest seedGuest creates (ct100).
	guestWeb = "web"
	// guestMine / guestSecret: one guest the client may reach and one it
	// may not, for the disclosure tests.
	guestMine   = "mine"
	guestSecret = "secret"
	// Instance names used by the disclosure tests.
	instMine   = "mine"
	instSecret = "secretnode"
	instRome   = "rome"
	instParis  = "paris"
	pveAPIURL  = "https://pve:8006"
	instPVE    = "pve"
	cmdGuestLs = "guest ls"
	// cmdConnectCT100 is the CLI form that replaced the bare "ct100"
	// argument.
	cmdConnectCT100 = "guest connect " + guestCT100
	// A guest identifier that matches nothing.
	guestMissing      = "ct999"
	cmdConnectMissing = "guest connect " + guestMissing
)

func newRepo(t *testing.T) db.Repository {
	t.Helper()
	repo, err := db.NewSQLiteRepository(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func addClient(t *testing.T, repo db.Repository, keys ...string) *models.Client {
	t.Helper()
	const name = userAlice
	if err := repo.AddClient(t.Context(), &models.Client{
		Name: name, PublicKeys: keys,
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}
	c, err := repo.GetClientByName(t.Context(), name)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	return c
}

// --- authorized keys ---------------------------------------------------

func TestAuthorizedKeysForClient(t *testing.T) {
	repo := newRepo(t)
	addClient(t, repo, "ssh-ed25519 AAAAone alice", "ssh-rsa AAAAtwo alice")

	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(t.Context(), &out, repo, userAlice, ""); err != nil {
		t.Fatalf("WriteAuthorizedKeys: %v", err)
	}
	lines := nonEmptyLines(out.String())
	if len(lines) != 2 {
		t.Fatalf("got %d key lines, want 2: %q", len(lines), out.String())
	}
}

// sshd parses stdout as keys, so an unknown user must produce no output and
// no error rather than a diagnostic.
func TestAuthorizedKeysUnknownUserIsSilent(t *testing.T) {
	repo := newRepo(t)

	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(t.Context(), &out, repo, "nobody", ""); err != nil {
		t.Fatalf("unknown user must not error, got %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("unknown user produced output: %q", out.String())
	}
}

func TestAuthorizedKeysAdminUsesFlagKey(t *testing.T) {
	repo := newRepo(t)
	const flagKey = "ssh-ed25519 AAAAflag admin"

	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(t.Context(), &out, repo, session.AdminUser, flagKey); err != nil {
		t.Fatalf("WriteAuthorizedKeys: %v", err)
	}
	if !strings.Contains(out.String(), flagKey) {
		t.Errorf("admin output %q does not contain the flag key", out.String())
	}
}

// The admin key never makes its holder into a client.
//
// The key IS offered under a client's name -- the name no longer filters
// the key set, since it no longer selects an identity -- but presenting it
// resolves to the administrator, not to that client. The old behavior
// (withholding it) had the perverse effect that an administrator could not
// log in under a name a client happened to own.
func TestAdminKeyUnderAClientNameStaysAdmin(t *testing.T) {
	repo := newRepo(t)
	addNamedClient(t, repo, userAlice, keyAlice)

	id, err := session.ResolveIdentityByKey(
		t.Context(), repo, userAlice, writeAuthInfo(t, keyAdmin), keyAdmin)
	if err != nil {
		t.Fatalf("ResolveIdentityByKey: %v", err)
	}
	if !id.IsAdmin {
		t.Error("the admin key must stay admin under a client's name")
	}
	if id.ClientID != 0 {
		t.Errorf("ClientID = %d, want 0", id.ClientID)
	}
}

// --- identity ----------------------------------------------------------

// The UI must name the identity the KEY resolves to, never the login name.
//
// The login name is an alias chosen by the caller, so showing it back would
// claim an account that was never defined. The same key must also produce
// the same display name under every name it arrives under.
func TestDisplayNameIsTheConfiguredName(t *testing.T) {
	repo := newRepo(t)
	addNamedClient(t, repo, userAlice, keyAlice)

	tests := []struct {
		name  string
		login string
		key   string
		want  string
	}{
		{"admin key, admin name", session.AdminUser, keyAdmin, session.AdminUser},
		{"admin key, an alias", userAlias, keyAdmin, session.AdminUser},
		// A second alias: were DisplayName echoing the login name, the
		// case above would pass while this one showed a different
		// "identity" for the very same administrator.
		{"admin key, another alias", "someone-else", keyAdmin, session.AdminUser},
		{"client key, own name", userAlice, keyAlice, userAlice},
		// The key wins: alice's key under the admin name is still alice.
		{"client key, admin name", session.AdminUser, keyAlice, userAlice},
		{"client key, an alias", userAlias, keyAlice, userAlice},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := session.ResolveIdentityByKey(
				t.Context(), repo, tc.login,
				writeAuthInfo(t, tc.key), keyAdmin)
			if err != nil {
				t.Fatalf("ResolveIdentityByKey(%q): %v", tc.login, err)
			}
			if id.DisplayName != tc.want {
				t.Errorf("login %q: DisplayName = %q, want %q",
					tc.login, id.DisplayName, tc.want)
			}
			// The login name is still carried separately: it is the audit
			// record of what actually came in, so collapsing the two would
			// lose it from the log.
			if id.User != tc.login {
				t.Errorf("login %q: User = %q, want the name as given",
					tc.login, id.User)
			}
		})
	}
}

// A client named "admin" would otherwise be routed as an administrator.
// cli.ValidateClientName prevents creating one, and this is the second line
// of defense for a database that predates that check.
func TestResolveIdentityRefusesShadowedAdmin(t *testing.T) {
	repo := newRepo(t)
	if err := repo.AddClient(t.Context(), &models.Client{
		Name:       session.AdminUser,
		PublicKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF x"},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}

	if _, err := session.ResolveIdentityByKey(
		t.Context(), repo, session.AdminUser,
		writeAuthInfo(t, keyAdmin), keyAdmin); err == nil {
		t.Fatal("a client shadowing the admin login must be refused")
	}
}

// A client shadowing the admin name must not gain admin.
//
// The defense is no longer that the key is withheld -- every key is offered
// for a name that is not a client's, because the name cannot identify
// anyone. It is that the SESSION resolves identity from the key, and that
// key belongs to a client row, so it can only ever produce a client
// identity. ResolveIdentity additionally refuses the shadowed name outright.
func TestAShadowingClientKeyNeverResolvesToAdmin(t *testing.T) {
	repo := newRepo(t)
	const attacker = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF attacker"
	if err := repo.AddClient(t.Context(), &models.Client{
		Name: session.AdminUser, PublicKeys: []string{attacker},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}

	// The login is refused outright. A client row named "admin" makes two
	// identities answer to one name, which is a misconfiguration rather
	// than a login to resolve -- so proxpass stops instead of deciding
	// which one was meant.
	id, err := session.ResolveIdentityByKey(
		t.Context(), repo, session.AdminUser, writeAuthInfo(t, attacker), "")
	if err == nil {
		t.Fatalf("a shadowed admin name must be refused, got admin=%v client=%d",
			id.IsAdmin, id.ClientID)
	}
	if !strings.Contains(err.Error(), "shadows") {
		t.Errorf("error does not explain the shadowing: %v", err)
	}

	// The property that must hold regardless: that key never yields admin.
	// Here it cannot even reach a decision, but the same key under a
	// non-shadowed database resolves to its client.
	repo2 := newRepo(t)
	c := addNamedClient(t, repo2, userAlice, attacker)
	id2, err := session.ResolveIdentityByKey(
		t.Context(), repo2, session.AdminUser, writeAuthInfo(t, attacker), "")
	if err != nil {
		t.Fatalf("ResolveIdentityByKey: %v", err)
	}
	if id2.IsAdmin || id2.ClientID != c.ID {
		t.Errorf("a client key under the admin name resolved to admin=%v client=%d",
			id2.IsAdmin, id2.ClientID)
	}
}

// A name that is not a client's is offered EVERY key, because the name
// identifies nobody and the session decides from the key.
//
// Withholding client keys here used to be the defense against a client
// reaching admin. That job now belongs to ResolveIdentityByKey, which is
// what makes it safe to let a client authenticate under any name -- and is
// what lets a client connect without spelling its own name out.
func TestAuthorizedKeysOffersEveryKeyForANonClientName(t *testing.T) {
	const (
		adminKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF admin"
		clientKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHixnSBaUZmAX3Qd4hYl71jjgr58KXAJTdKjFrax6FHN alice"
	)
	repo := newRepo(t)
	addClient(t, repo, clientKey)

	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(
		t.Context(), &out, repo, userAlias, adminKey); err != nil {
		t.Fatalf("WriteAuthorizedKeys: %v", err)
	}
	if !strings.Contains(out.String(), adminKey) {
		t.Errorf("the admin key was not offered for an alias: %q", out.String())
	}
	if !strings.Contains(out.String(), clientKey) {
		t.Errorf("the client key was not offered for an alias, so the client "+
			"cannot log in without naming itself: %q", out.String())
	}

	// The security property that matters: presenting the CLIENT key under
	// that alias yields the client, not the administrator.
	id, err := session.ResolveIdentityByKey(
		t.Context(), repo, userAlias, writeAuthInfo(t, clientKey), adminKey)
	if err != nil {
		t.Fatalf("ResolveIdentityByKey: %v", err)
	}
	if id.IsAdmin {
		t.Error("a client key under an alias resolved to the administrator")
	}
	if id.DisplayName != userAlice {
		t.Errorf("DisplayName = %q, want %q", id.DisplayName, userAlice)
	}
}

// A client's key resolves to that client and is never promoted to admin,
// whatever name it arrives under.
func TestClientKeyIsNeverPromotedToAdmin(t *testing.T) {
	repo := newRepo(t)
	addNamedClient(t, repo, userAlice, keyAlice)

	id, err := session.ResolveIdentityByKey(
		t.Context(), repo, userAlice, writeAuthInfo(t, keyAlice), keyAdmin)
	if err != nil {
		t.Fatalf("ResolveIdentityByKey: %v", err)
	}
	if id.IsAdmin {
		t.Error("a client login must not resolve to the administrator")
	}
}

// --- session routing ---------------------------------------------------

type terminalBuf struct {
	out  bytes.Buffer
	errb bytes.Buffer
	term *console.Terminal
}

func newTerminal(input string) *terminalBuf {
	tb := &terminalBuf{}
	tb.term = &console.Terminal{
		In:     strings.NewReader(input),
		Out:    &tb.out,
		Err:    &tb.errb,
		Term:   "xterm",
		Width:  80,
		Height: 24,
	}
	return tb
}

func newDeps(repo db.Repository, tb *terminalBuf, proxier console.Proxier) *session.Deps {
	d := &session.Deps{
		Repo:     repo,
		Proxier:  proxier,
		Logger:   log.New(io.Discard, "", 0),
		Terminal: tb.term,
	}
	// A database-backed directory that reads the identity from Deps when
	// it is used, not when it is built: tests routinely set IsAdmin or
	// ClientID after this returns, and capturing them here would silently
	// scope the session to the wrong caller.
	d.Dir = &lazyRepoDirectory{deps: d}
	return d
}

// lazyRepoDirectory is a RepoDirectory that picks up the identity at call
// time.
type lazyRepoDirectory struct {
	deps *session.Deps
}

func (l *lazyRepoDirectory) dir() *session.RepoDirectory {
	return &session.RepoDirectory{
		Repo:     l.deps.Repo,
		IsAdmin:  l.deps.IsAdmin,
		ClientID: l.deps.ClientID,
	}
}

func (l *lazyRepoDirectory) AccessibleGuests(ctx context.Context) ([]*session.GuestInfo, error) {
	return l.dir().AccessibleGuests(ctx)
}

func (l *lazyRepoDirectory) Connect(ctx context.Context, guestID int64) (*session.ConnectInfo, error) {
	return l.dir().Connect(ctx, guestID)
}

func (l *lazyRepoDirectory) IsLoginNameReserved(ctx context.Context, name string) (bool, error) {
	return l.dir().IsLoginNameReserved(ctx, name)
}

func (l *lazyRepoDirectory) PublicEndpoint(ctx context.Context) (string, error) {
	return l.dir().PublicEndpoint(ctx)
}

func seedGuest(t *testing.T, repo db.Repository) *models.Guest {
	t.Helper()
	inst := &models.ProxmoxInstance{
		Name: instPVE, APIURL: pveAPIURL, Node: instPVE,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	guest := &models.Guest{
		Type: models.GuestTypeCT, Name: guestWeb, Status: models.StatusRunning,
		ProxmoxID: 100, InstanceID: inst.ID,
	}
	if err := repo.UpsertGuest(t.Context(), guest); err != nil {
		t.Fatalf("upsert guest: %v", err)
	}
	guests, _ := repo.ListGuests(t.Context())
	return guests[0]
}

// --- login name as a guest identifier ----------------------------------

// seedGuestOn adds a guest to an existing instance.
func seedGuestOn(
	t *testing.T, repo db.Repository, instID int64,
	typ models.GuestType, vmid int, name string,
) {
	t.Helper()
	if err := repo.UpsertGuest(t.Context(), &models.Guest{
		Type: typ, Name: name, Status: models.StatusRunning,
		ProxmoxID: vmid, InstanceID: instID,
	}); err != nil {
		t.Fatalf("upsert guest %s%d: %v", typ, vmid, err)
	}
}

// "ssh ct100@host" connects straight to the guest: the login name is itself
// a guest identifier, in every form the resolver accepts.
//
// This is the shorthand that predates the sshd rework. It is reachable only
// because the directory serves any unused name over NSS, so sshd gets far
// enough to run the session at all.
func TestLoginNameConnectsToTheGuest(t *testing.T) {
	for _, login := range []string{guestCT100, "100", guestWeb, "CT100", "Web"} {
		t.Run(login, func(t *testing.T) {
			repo := newRepo(t)
			guest := seedGuest(t, repo)

			proxier := &testenv.MockProxier{}
			tb := newTerminal("")
			d := newDeps(repo, tb, proxier)
			d.User = login
			d.IsAdmin = true
			// No command at all: this is a bare "ssh <name>@host".
			d.Command = ""

			if code := session.Run(t.Context(), d); code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
			}
			sessions := proxierSessions(proxier)
			if len(sessions) != 1 {
				t.Fatalf("login %q opened %d consoles, want 1 (stderr: %q)",
					login, len(sessions), tb.errb.String())
			}
			if sessions[0].ProxmoxID != guest.ProxmoxID {
				t.Errorf("connected to vmid %d, want %d",
					sessions[0].ProxmoxID, guest.ProxmoxID)
			}
			// The picker must not have been drawn: the name was understood.
			if strings.Contains(tb.out.String(), "guests available to") {
				t.Errorf("the picker was shown for a guest login name: %q", tb.out.String())
			}
		})
	}
}

// A login name that names no guest still reaches the picker.
//
// This is the common case -- "ssh admin@host" or any admin alias -- so a
// miss must not be an error. Were it one, resolving the login name would
// have broken every browsing login.
func TestNonGuestLoginNameShowsThePicker(t *testing.T) {
	for _, login := range []string{session.AdminUser, "tobias", "nosuchguest"} {
		t.Run(login, func(t *testing.T) {
			repo := newRepo(t)
			seedGuest(t, repo)

			proxier := &testenv.MockProxier{}
			tb := newTerminal("\x03") // Ctrl+C: quit the picker
			tb.term.Raw = true
			d := newDeps(repo, tb, proxier)
			d.User = login
			d.IsAdmin = true

			if code := session.Run(t.Context(), d); code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
			}
			if !strings.Contains(tb.out.String(), "guests available to") {
				t.Errorf("login %q did not reach the picker: %q", login, tb.out.String())
			}
			if len(proxier.Sessions) != 0 {
				t.Error("quitting the picker must not open a console")
			}
		})
	}
}

// An ambiguous login name must be reported, never guessed at.
//
// "ct100" can exist on two instances, and a login name has no room for an
// instance prefix (a colon cannot appear in one -- see api.ValidLoginName),
// so this is a dead end by design. Connecting to an arbitrary match would
// put the user on the wrong machine; falling back to the picker would hide
// that the name meant something.
func TestAmbiguousLoginNameIsReported(t *testing.T) {
	repo := newRepo(t)
	first := seedGuest(t, repo) // ct100 "web" on instance pve

	// A distinct API URL: the schema requires it to be unique.
	second := &models.ProxmoxInstance{
		Name: instRome, APIURL: "https://rome:8006", Node: instRome,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	if err := repo.AddProxmoxInstance(t.Context(), second); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	seedGuestOn(t, repo, second.ID, models.GuestTypeCT, first.ProxmoxID, first.Name)

	for _, login := range []string{guestCT100, "100", guestWeb} {
		t.Run(login, func(t *testing.T) {
			proxier := &testenv.MockProxier{}
			tb := newTerminal("\x03")
			tb.term.Raw = true
			d := newDeps(repo, tb, proxier)
			d.User = login
			d.IsAdmin = true

			if code := session.Run(t.Context(), d); code == 0 {
				t.Errorf("an ambiguous login name must fail, got 0 (out: %q)", tb.out.String())
			}
			if len(proxier.Sessions) != 0 {
				t.Errorf("an ambiguous name must not connect anywhere: %+v",
					proxierSessions(proxier))
			}
			// It must say what is wrong, not silently show the picker.
			if !strings.Contains(tb.errb.String(), "matches") {
				t.Errorf("stderr does not explain the ambiguity: %q", tb.errb.String())
			}
			// The advice must be typeable AS A LOGIN NAME. The old
			// "instance:identifier" could not be -- a colon is not a legal
			// login name character -- which is why the qualifier is now a
			// "@" suffix.
			if strings.Contains(tb.errb.String(), "instance:identifier") {
				t.Errorf("suggested a prefix a login name cannot carry: %q",
					tb.errb.String())
			}
			// The alternatives must be distinguishable. Listing bare ids
			// for an ambiguous "ct100" would print "ct100, ct100", so the
			// instance name has to be part of each one.
			for _, want := range []string{"ct100@pve", "ct100@rome"} {
				if !strings.Contains(tb.errb.String(), want) {
					t.Errorf("stderr does not list %q among the alternatives: %q",
						want, tb.errb.String())
				}
			}
			if !strings.Contains(tb.errb.String(), "pick from the list") {
				t.Errorf("stderr does not offer the picker as a way out: %q",
					tb.errb.String())
			}
			if strings.Contains(tb.out.String(), "guests available to") {
				t.Errorf("an ambiguous name must not fall back to the picker: %q",
					tb.out.String())
			}
		})
	}
}

// The access check is enforced on the login-name path too.
//
// A client cannot actually reach this in the shipped image: a guest name is
// not a client name, so the directory serves it as an admin alias and
// WriteAuthorizedKeys offers only admin keys for it -- sshd rejects a
// client's key before the session starts (verified against the running
// image). The check is still required here, because that is an
// authentication property rather than one of this function, and Deps is
// also constructed by other callers.
func TestLoginNameRespectsClientAccess(t *testing.T) {
	t.Run("granted", func(t *testing.T) {
		repo := newRepo(t)
		client := addClient(t, repo)
		guest := seedGuest(t, repo)
		if err := repo.GrantClientAccess(
			t.Context(), client.ID, []int64{guest.ID}); err != nil {
			t.Fatalf("grant access: %v", err)
		}

		proxier := &testenv.MockProxier{}
		tb := newTerminal("")
		d := newDeps(repo, tb, proxier)
		// A client connecting under a guest's name rather than its own.
		d.User = guestCT100
		d.ClientID = client.ID

		if code := session.Run(t.Context(), d); code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
		}
		if len(proxierSessions(proxier)) != 1 {
			t.Error("a permitted client must reach the guest by login name")
		}
	})

	// A guest the client may NOT reach must be indistinguishable from one
	// that does not exist.
	//
	// The login name is attacker-chosen and free to try, so answering
	// "access denied" for a real guest and showing the picker for an
	// invented one would be an enumeration oracle: repeat it and the whole
	// estate falls out, including guests and instance names the caller was
	// never entitled to know about. Both cases must look the same.
	t.Run("no access is indistinguishable from no such guest", func(t *testing.T) {
		repo := newRepo(t)
		client := addClient(t, repo)
		// A second guest the client CAN reach, so the picker has content
		// and both branches render the same frame.
		inst := &models.ProxmoxInstance{
			Name: instPVE, APIURL: pveAPIURL, Node: instPVE,
			ConnectionType: models.ConnectionTypeTermProxy,
		}
		if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
			t.Fatalf("add instance: %v", err)
		}
		seedGuestOn(t, repo, inst.ID, models.GuestTypeCT, 100, guestSecret)
		seedGuestOn(t, repo, inst.ID, models.GuestTypeVM, 200, guestMine)
		guests, _ := repo.ListGuests(t.Context())
		for _, g := range guests {
			if g.Name == guestMine {
				if err := repo.GrantClientAccess(
					t.Context(), client.ID, []int64{g.ID}); err != nil {
					t.Fatalf("grant: %v", err)
				}
			}
		}

		outputs := make(map[string]string, 2)
		for _, login := range []string{guestSecret, "nosuchguest"} {
			proxier := &testenv.MockProxier{}
			tb := newTerminal("\x03")
			tb.term.Raw = true
			d := newDeps(repo, tb, proxier)
			d.User = login
			d.DisplayName = userAlice
			d.ClientID = client.ID

			_ = session.Run(t.Context(), d)

			if len(proxier.Sessions) != 0 {
				t.Errorf("login %q reached a console it has no access to", login)
			}
			if strings.Contains(tb.errb.String(), "access denied") {
				t.Errorf("login %q revealed that the guest exists: %q",
					login, tb.errb.String())
			}
			if strings.Contains(tb.out.String(), guestSecret) {
				t.Errorf("login %q leaked an inaccessible guest name: %q",
					login, tb.out.String())
			}
			outputs[login] = tb.out.String()
		}

		// The decisive assertion: the two cases must be byte-identical.
		if outputs[guestSecret] != outputs["nosuchguest"] {
			t.Errorf("an existing but inaccessible guest is distinguishable "+
				"from a nonexistent one:\n existing: %q\n absent:   %q",
				outputs[guestSecret], outputs["nosuchguest"])
		}
	})
}

// An ambiguity must only ever name guests the caller may already see.
//
// The hint lists qualified ids like "ct100@pve, ct100@rome", which includes
// INSTANCE names. Resolving against every guest would therefore disclose
// both guests and Proxmox instances the caller has no access to, just by
// logging in under a colliding name.
func TestAmbiguityHintOnlyNamesAccessibleGuests(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)

	// Same name "web" on two instances; the client may reach only one.
	mine := &models.ProxmoxInstance{
		Name: instMine, APIURL: "https://mine:8006", Node: instMine,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	secret := &models.ProxmoxInstance{
		Name: instSecret, APIURL: "https://secret:8006", Node: instSecret,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	for _, i := range []*models.ProxmoxInstance{mine, secret} {
		if err := repo.AddProxmoxInstance(t.Context(), i); err != nil {
			t.Fatalf("add instance: %v", err)
		}
	}
	seedGuestOn(t, repo, mine.ID, models.GuestTypeCT, 100, "web")
	seedGuestOn(t, repo, secret.ID, models.GuestTypeCT, 100, "web")
	guests, _ := repo.ListGuests(t.Context())
	for _, g := range guests {
		if g.InstanceID == mine.ID {
			if err := repo.GrantClientAccess(
				t.Context(), client.ID, []int64{g.ID}); err != nil {
				t.Fatalf("grant: %v", err)
			}
		}
	}

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	d.User = "web"
	d.DisplayName = userAlice
	d.ClientID = client.ID

	// Only ONE "web" is reachable, so this must connect, not report an
	// ambiguity: the inaccessible twin is not the caller's business.
	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr %q)", code, tb.errb.String())
	}
	all := tb.out.String() + tb.errb.String()
	if strings.Contains(all, instSecret) {
		t.Errorf("leaked an instance the client cannot see: %q", all)
	}
	if strings.Contains(all, "matches 2 guests") {
		t.Errorf("reported an ambiguity against an inaccessible guest: %q", all)
	}
	sessions := proxierSessions(proxier)
	if len(sessions) != 1 {
		t.Fatalf("want exactly one console, got %d", len(sessions))
	}
}

// A login name may now carry an instance: "ct100@rome".
//
// This is what the "@" separator buys. The old "instance:identifier" form
// could never be a login name, because a colon is the passwd field
// separator, so a collision was simply a dead end from the login path.
func TestQualifiedLoginNameSelectsTheInstance(t *testing.T) {
	repo := newRepo(t)
	rome := &models.ProxmoxInstance{
		Name: instRome, APIURL: "https://rome:8006", Node: instRome,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	paris := &models.ProxmoxInstance{
		Name: instParis, APIURL: "https://paris:8006", Node: instParis,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	for _, i := range []*models.ProxmoxInstance{rome, paris} {
		if err := repo.AddProxmoxInstance(t.Context(), i); err != nil {
			t.Fatalf("add instance: %v", err)
		}
	}
	// The same ct100 on both, so the bare name is ambiguous.
	seedGuestOn(t, repo, rome.ID, models.GuestTypeCT, 100, guestWeb)
	seedGuestOn(t, repo, paris.ID, models.GuestTypeCT, 100, guestWeb)

	for _, tc := range []struct {
		login string
		want  int64
	}{
		{"ct100@rome", rome.ID},
		{"ct100@paris", paris.ID},
		{"web@rome", rome.ID},
		{"100@paris", paris.ID},
		// Case-insensitive on both halves.
		{"CT100@Rome", rome.ID},
	} {
		t.Run(tc.login, func(t *testing.T) {
			proxier := &testenv.MockProxier{}
			tb := newTerminal("")
			d := newDeps(repo, tb, proxier)
			d.User = tc.login
			d.DisplayName = session.AdminUser
			d.IsAdmin = true

			if code := session.Run(t.Context(), d); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr %q)", code, tb.errb.String())
			}
			sessions := proxierSessions(proxier)
			if len(sessions) != 1 {
				t.Fatalf("opened %d consoles, want 1", len(sessions))
			}
			if sessions[0].InstanceID != tc.want {
				t.Errorf("connected to instance %d, want %d",
					sessions[0].InstanceID, tc.want)
			}
		})
	}
}

// The instance suffix must not become an oracle on instance names.
//
// Only instances hosting a guest the caller can reach count as separators.
// Otherwise "x@rome" behaving differently from "x@nope" would reveal that
// "rome" exists -- the same disclosure the guest scoping exists to prevent.
func TestQualifiedLoginNameDoesNotDiscloseInstances(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	mine := &models.ProxmoxInstance{
		Name: instMine, APIURL: "https://mine:8006", Node: instMine,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	secret := &models.ProxmoxInstance{
		Name: instSecret, APIURL: "https://secret:8006", Node: instSecret,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	for _, i := range []*models.ProxmoxInstance{mine, secret} {
		if err := repo.AddProxmoxInstance(t.Context(), i); err != nil {
			t.Fatalf("add instance: %v", err)
		}
	}
	seedGuestOn(t, repo, mine.ID, models.GuestTypeCT, 100, guestMine)
	seedGuestOn(t, repo, secret.ID, models.GuestTypeCT, 200, guestSecret)
	guests, _ := repo.ListGuests(t.Context())
	for _, g := range guests {
		if g.InstanceID == mine.ID {
			if err := repo.GrantClientAccess(
				t.Context(), client.ID, []int64{g.ID}); err != nil {
				t.Fatalf("grant: %v", err)
			}
		}
	}

	// A real instance the client cannot see, and an invented one: both must
	// behave identically.
	outputs := make(map[string]string, 2)
	for _, login := range []string{"x@" + instSecret, "x@nosuchnode"} {
		tb := newTerminal("\x03")
		tb.term.Raw = true
		proxier := &testenv.MockProxier{}
		d := newDeps(repo, tb, proxier)
		d.User = login
		d.DisplayName = userAlice
		d.ClientID = client.ID

		_ = session.Run(t.Context(), d)
		if len(proxier.Sessions) != 0 {
			t.Errorf("login %q connected somewhere", login)
		}
		if strings.Contains(tb.out.String()+tb.errb.String(), guestSecret) {
			t.Errorf("login %q leaked an inaccessible guest", login)
		}
		outputs[login] = tb.out.String() + tb.errb.String()
	}
	if outputs["x@"+instSecret] != outputs["x@nosuchnode"] {
		t.Errorf("an invisible instance is distinguishable from a "+
			"nonexistent one:\n real:    %q\n invented: %q",
			outputs["x@"+instSecret], outputs["x@nosuchnode"])
	}
}

// A guest must never hijack a reserved login name.
//
// Guest names come from Proxmox discovery, so proxpass does not control
// them. A guest called "admin" -- or named after a client -- would
// otherwise steal the documented browse login from whoever it belongs to.
func TestReservedLoginNamesAreNeverTreatedAsGuests(t *testing.T) {
	for _, reserved := range []string{session.AdminUser, userAlice} {
		t.Run(reserved, func(t *testing.T) {
			repo := newRepo(t)
			addClient(t, repo) // a client named "alice"
			inst := &models.ProxmoxInstance{
				Name: instPVE, APIURL: pveAPIURL, Node: instPVE,
				ConnectionType: models.ConnectionTypeTermProxy,
			}
			if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
				t.Fatalf("add instance: %v", err)
			}
			// A guest named exactly like the reserved login name.
			seedGuestOn(t, repo, inst.ID, models.GuestTypeCT, 100, reserved)

			proxier := &testenv.MockProxier{}
			tb := newTerminal("\x03")
			tb.term.Raw = true
			d := newDeps(repo, tb, proxier)
			d.User = reserved
			d.DisplayName = session.AdminUser
			d.IsAdmin = true

			if code := session.Run(t.Context(), d); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr %q)", code, tb.errb.String())
			}
			if len(proxier.Sessions) != 0 {
				t.Errorf("login %q connected to a guest instead of browsing", reserved)
			}
			if !strings.Contains(tb.out.String(), "guests available to") {
				t.Errorf("login %q did not reach the picker: %q", reserved, tb.out.String())
			}
		})
	}
}

// Reserved names are matched case-insensitively, since guest resolution is
// too: a guest called "Admin" must not slip through.
func TestReservedLoginNameMatchIsCaseInsensitive(t *testing.T) {
	repo := newRepo(t)
	inst := &models.ProxmoxInstance{
		Name: instPVE, APIURL: pveAPIURL, Node: instPVE,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	seedGuestOn(t, repo, inst.ID, models.GuestTypeCT, 100, "Admin")

	proxier := &testenv.MockProxier{}
	tb := newTerminal("\x03")
	tb.term.Raw = true
	d := newDeps(repo, tb, proxier)
	d.User = "Admin"
	d.DisplayName = session.AdminUser
	d.IsAdmin = true

	_ = session.Run(t.Context(), d)
	if len(proxier.Sessions) != 0 {
		t.Error(`a guest named "Admin" hijacked the admin login`)
	}
}

// An explicit command still wins over the login name, so the documented
// "ssh alice@host ct100" form keeps working unchanged.
func TestExplicitCommandTakesPrecedenceOverTheLoginName(t *testing.T) {
	repo := newRepo(t)
	inst := &models.ProxmoxInstance{
		Name: instPVE, APIURL: pveAPIURL, Node: instPVE,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	seedGuestOn(t, repo, inst.ID, models.GuestTypeCT, 100, "web")
	seedGuestOn(t, repo, inst.ID, models.GuestTypeVM, 200, "db")

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	// Login name names one guest, the command names another: the command
	// is the explicit request and must win.
	d.User = guestCT100
	d.IsAdmin = true
	d.Command = "guest connect vm200"

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
	}
	sessions := proxierSessions(proxier)
	if len(sessions) != 1 || sessions[0].ProxmoxID != 200 {
		t.Errorf("connected to %+v, want vmid 200 from the command", sessions)
	}
}

// A client must not reach any admin command.
//
// Clients now have a CLI of their own, so the test is no longer "any
// multi-word command fails" -- it is that only the client tree exists for
// them. The tree is built separately rather than filtered from the admin
// one, so a command added for admins is not reachable here by default.
func TestClientCannotRunAdminCommands(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)

	for _, cmd := range []string{
		"instance ls",
		"client ls",
		"client add --name bob --key x",
		"group ls",
		"access ls",
		"access grant --client alice --guest ct100",
		"policy show",
		"admin-key ls",
		"discover",
		// A guest subcommand that exists for admins but not for clients.
		"guest inspect ct100",
	} {
		t.Run(cmd, func(t *testing.T) {
			tb := newTerminal("")
			d := newDeps(repo, tb, &testenv.MockProxier{})
			d.User = userAlice
			d.DisplayName = userAlice
			d.ClientID = client.ID
			d.Command = cmd

			if code := session.Run(t.Context(), d); code == 0 {
				t.Errorf("a client ran %q successfully (out: %q)", cmd, tb.out.String())
			}
			// It must not have executed: no listing, no mutation.
			if strings.Contains(tb.out.String(), "TYPE") ||
				strings.Contains(tb.out.String(), "added") {
				t.Errorf("a client saw admin output for %q: %q", cmd, tb.out.String())
			}
		})
	}
}

// A client's own "guest ls" shows only the guests it may reach.
//
// This is the command's whole premise: it is built against a pre-filtered
// pool, so it cannot list anything the picker would not.
func TestClientGuestLsIsScopedToItsAccess(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	inst := &models.ProxmoxInstance{
		Name: instPVE, APIURL: pveAPIURL, Node: instPVE,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	seedGuestOn(t, repo, inst.ID, models.GuestTypeCT, 100, guestMine)
	seedGuestOn(t, repo, inst.ID, models.GuestTypeCT, 200, guestSecret)
	guests, _ := repo.ListGuests(t.Context())
	for _, g := range guests {
		if g.Name == guestMine {
			if err := repo.GrantClientAccess(
				t.Context(), client.ID, []int64{g.ID}); err != nil {
				t.Fatalf("grant: %v", err)
			}
		}
	}

	tb := newTerminal("")
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.User = userAlice
	d.DisplayName = userAlice
	d.ClientID = client.ID
	d.Command = cmdGuestLs

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr %q)", code, tb.errb.String())
	}
	out := tb.out.String()
	if !strings.Contains(out, guestMine) {
		t.Errorf("own guest missing from the listing: %q", out)
	}
	if strings.Contains(out, guestSecret) {
		t.Errorf("listing leaked an inaccessible guest: %q", out)
	}
}

// A client may connect through the CLI, for the guests it may reach.
func TestClientCanConnectThroughTheCLI(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	guest := seedGuest(t, repo)
	if err := repo.GrantClientAccess(
		t.Context(), client.ID, []int64{guest.ID}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	proxier := &testenv.MockProxier{}
	tb := newTerminal("")
	d := newDeps(repo, tb, proxier)
	d.User = userAlice
	d.DisplayName = userAlice
	d.ClientID = client.ID
	d.Command = cmdConnectCT100

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr %q)", code, tb.errb.String())
	}
	if len(proxierSessions(proxier)) != 1 {
		t.Error("a permitted client must reach the guest through the CLI")
	}
}

// A guest the client may not reach is not found rather than denied, so the
// CLI is not an oracle either.
func TestClientCLIConnectDoesNotDiscloseInaccessibleGuests(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	seedGuest(t, repo) // exists, no access rule

	outputs := make(map[string]string, 2)
	for _, cmd := range []string{cmdConnectCT100, cmdConnectMissing} {
		tb := newTerminal("")
		proxier := &testenv.MockProxier{}
		d := newDeps(repo, tb, proxier)
		d.User = userAlice
		d.DisplayName = userAlice
		d.ClientID = client.ID
		d.Command = cmd

		if code := session.Run(t.Context(), d); code == 0 {
			t.Errorf("%q must fail", cmd)
		}
		if len(proxier.Sessions) != 0 {
			t.Errorf("%q reached a console", cmd)
		}
		if strings.Contains(tb.errb.String(), "access denied") {
			t.Errorf("%q revealed that the guest exists: %q", cmd, tb.errb.String())
		}
		outputs[cmd] = tb.errb.String()
	}
	// The messages differ only by the identifier the caller supplied, which
	// they already knew. Normalizing that away, the two must be identical:
	// neither reveals whether the guest exists.
	norm := func(s, id string) string { return strings.ReplaceAll(s, id, "<id>") }
	gotExisting := norm(outputs[cmdConnectCT100], guestCT100)
	gotAbsent := norm(outputs[cmdConnectMissing], guestMissing)
	if gotExisting != gotAbsent {
		t.Errorf("an inaccessible guest is distinguishable from a "+
			"nonexistent one:\n existing: %q\n absent:   %q",
			gotExisting, gotAbsent)
	}
}

// A client with no access rule must be refused even when the guest exists.
func TestClientWithoutAccessIsDenied(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	seedGuest(t, repo)

	tb := newTerminal("")
	proxier := &testenv.MockProxier{}
	d := newDeps(repo, tb, proxier)
	d.User = userAlice
	d.ClientID = client.ID
	d.Command = cmdConnectCT100

	if code := session.Run(t.Context(), d); code == 0 {
		t.Error("client without access must be denied")
	}
	if len(proxier.Sessions) != 0 {
		t.Error("denied client must not reach the console")
	}
}

func TestClientWithAccessConnects(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	guest := seedGuest(t, repo)
	if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{guest.ID}); err != nil {
		t.Fatalf("grant access: %v", err)
	}

	tb := newTerminal("")
	proxier := &testenv.MockProxier{}
	d := newDeps(repo, tb, proxier)
	d.User = userAlice
	d.ClientID = client.ID
	d.Command = cmdConnectCT100

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
	}
	if len(proxier.Sessions) != 1 {
		t.Fatalf("got %d console sessions, want 1", len(proxier.Sessions))
	}
	if proxier.Sessions[0].ProxmoxID != 100 {
		t.Errorf("connected to vmid %d, want 100", proxier.Sessions[0].ProxmoxID)
	}
}

// Admins bypass access rules.
func TestAdminConnectsWithoutAccessRule(t *testing.T) {
	repo := newRepo(t)
	seedGuest(t, repo)

	tb := newTerminal("")
	proxier := &testenv.MockProxier{}
	d := newDeps(repo, tb, proxier)
	d.User = session.AdminUser
	d.IsAdmin = true
	d.Command = cmdConnectCT100

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
	}
	if len(proxier.Sessions) != 1 {
		t.Errorf("got %d console sessions, want 1", len(proxier.Sessions))
	}
}

// With no command the session offers a picker; selecting an entry connects.
func TestPickerConnectsToSelection(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	guest := seedGuest(t, repo)
	if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{guest.ID}); err != nil {
		t.Fatalf("grant access: %v", err)
	}

	tb := newTerminal("1\n")
	proxier := &testenv.MockProxier{}
	d := newDeps(repo, tb, proxier)
	d.User = userAlice
	d.ClientID = client.ID

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
	}
	if len(proxier.Sessions) != 1 {
		t.Fatalf("got %d console sessions, want 1", len(proxier.Sessions))
	}
	if !strings.Contains(tb.out.String(), "web") {
		t.Errorf("picker output %q does not list the guest", tb.out.String())
	}
}

// The picker must only offer guests the client may actually reach.
func TestPickerHidesInaccessibleGuests(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	seedGuest(t, repo)

	tb := newTerminal("")
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.User = userAlice
	d.ClientID = client.ID

	if code := session.Run(t.Context(), d); code == 0 {
		t.Error("picker with no accessible guests must fail")
	}
	if strings.Contains(tb.out.String(), "web") {
		t.Error("picker listed a guest the client cannot access")
	}
}

// A PTY in raw mode has ICRNL disabled, so Enter arrives as a bare "\r".
// bufio.ScanLines only breaks on "\n", so the picker used to block until EOF
// and the documented "ssh <user>@host" workflow hung on every real terminal.
//
// The input must come from a reader that STAYS OPEN after the keystrokes,
// like a terminal does. With a strings.Reader, EOF terminates the line and
// even ScanLines appears to work, which is exactly why the original bug was
// not caught.
func TestPickerAcceptsCarriageReturn(t *testing.T) {
	for what, input := range map[string]string{
		"bare CR (raw mode)": "1\r",
		"CRLF":               "1\r\n",
		"LF":                 "1\n",
	} {
		input := input
		t.Run(what, func(t *testing.T) {
			repo := newRepo(t)
			client := addClient(t, repo)
			guest := seedGuest(t, repo)
			if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{guest.ID}); err != nil {
				t.Fatalf("grant access: %v", err)
			}

			// The keystrokes arrive on a pipe that STAYS OPEN, exactly as a
			// terminal's input does, so the picker cannot fall back on EOF
			// to terminate the line. The pipe is closed only once a console
			// session has actually started, which is what lets the mock
			// proxier (it echoes until its input ends) return.
			proxier := &testenv.MockProxier{}
			pr, pw := io.Pipe()
			t.Cleanup(func() { _ = pw.Close() })
			go func() {
				_, _ = pw.Write([]byte(input))
				// Wait for the selection to be acted on, then end the
				// console session. If the picker never read the line this
				// never fires and the test times out, which is the point.
				for i := 0; i < 200; i++ {
					if len(proxierSessions(proxier)) > 0 {
						_ = pw.Close()
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}()

			tb := newTerminal("")
			tb.term.In = pr
			d := newDeps(repo, tb, proxier)
			d.User = userAlice
			d.ClientID = client.ID

			done := make(chan int, 1)
			go func() { done <- session.Run(t.Context(), d) }()

			select {
			case code := <-done:
				if code != 0 {
					t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the picker hung: Enter was not accepted as a line terminator")
			}
			if len(proxier.Sessions) != 1 {
				t.Fatalf("got %d console sessions, want 1", len(proxier.Sessions))
			}
		})
	}
}

func TestQuitFromPicker(t *testing.T) {
	// Both line endings must work: a raw-mode terminal sends a bare CR.
	for what, input := range map[string]string{"LF": "q\n", "CR": "q\r"} {
		t.Run(what, func(t *testing.T) {
			repo := newRepo(t)
			client := addClient(t, repo)
			guest := seedGuest(t, repo)
			if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{guest.ID}); err != nil {
				t.Fatalf("grant access: %v", err)
			}

			tb := newTerminal(input)
			proxier := &testenv.MockProxier{}
			d := newDeps(repo, tb, proxier)
			d.User = userAlice
			d.ClientID = client.ID

			if code := session.Run(t.Context(), d); code != 0 {
				t.Errorf("quitting must exit cleanly, got %d", code)
			}
			if len(proxier.Sessions) != 0 {
				t.Error("quitting must not open a console")
			}
		})
	}
}

func TestHelpListsAccessibleGuests(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	guest := seedGuest(t, repo)
	if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{guest.ID}); err != nil {
		t.Fatalf("grant access: %v", err)
	}

	tb := newTerminal("")
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.User = userAlice
	d.ClientID = client.ID
	d.Command = "--help"

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("help exit code = %d, want 0", code)
	}
	if !strings.Contains(tb.errb.String(), "web") {
		t.Errorf("help output %q does not list the guest", tb.errb.String())
	}
}

func TestUnknownGuestFails(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	tb := newTerminal("")

	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.User = userAlice
	d.ClientID = client.ID
	d.Command = cmdConnectMissing

	if code := session.Run(t.Context(), d); code == 0 {
		t.Error("unknown guest must fail")
	}
}

// An SSH public key contains spaces, so quoted arguments must survive the
// split intact. Naive whitespace splitting tore keys apart and made
// "client add --key ..." fail with "no key found".
func TestAdminCanAddAClientWithAQuotedKey(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF alice@host"

	for _, tc := range []struct {
		name string
		cmd  string
	}{
		{"double quotes", `client add --name alice --key "` + key + `"`},
		{"single quotes", `client add --name alice --key '` + key + `'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo(t)
			tb := newTerminal("")
			d := newDeps(repo, tb, &testenv.MockProxier{})
			d.User = session.AdminUser
			d.IsAdmin = true
			d.Command = tc.cmd

			if code := session.Run(t.Context(), d); code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
			}
			client, err := repo.GetClientByName(t.Context(), userAlice)
			if err != nil {
				t.Fatalf("client was not created: %v", err)
			}
			if len(client.PublicKeys) != 1 || client.PublicKeys[0] != key {
				t.Errorf("stored keys = %q, want the single key %q",
					client.PublicKeys, key)
			}
		})
	}
}

// proxierSessions snapshots the mock's recorded sessions.
func proxierSessions(p *testenv.MockProxier) []testenv.MockProxySession {
	return p.SessionsSnapshot()
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// --- interactive picker ------------------------------------------------

// seedNamedGuest adds a running guest with a given name and vmid.
func seedNamedGuest(t *testing.T, repo db.Repository, instID int64, name string, vmid int) {
	t.Helper()
	g := &models.Guest{
		Type: models.GuestTypeCT, Name: name, Status: models.StatusRunning,
		ProxmoxID: vmid, InstanceID: instID,
	}
	if err := repo.UpsertGuest(t.Context(), g); err != nil {
		t.Fatalf("upsert guest %s: %v", name, err)
	}
}

// Drives the interactive picker the way a real terminal does: raw mode, keys
// arriving one at a time on a stream that stays open. Typing a filter and
// pressing Enter must connect to the matching guest.
//
// This is the regression test for the picker losing its filter: with the
// plain numbered prompt there was no way to narrow a 50-guest list at all.
func TestInteractivePickerFiltersAndConnects(t *testing.T) {
	repo := newRepo(t)
	inst := &models.ProxmoxInstance{
		Name: instPVE, APIURL: pveAPIURL, Node: instPVE,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	seedNamedGuest(t, repo, inst.ID, "alpha", 100)
	seedNamedGuest(t, repo, inst.ID, "mautrix-whatsapp", 101)
	seedNamedGuest(t, repo, inst.ID, "zulu", 102)

	proxier := &testenv.MockProxier{}
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })

	tb := newTerminal("")
	tb.term.In = pr
	tb.term.Raw = true // a PTY in raw mode, as sshd hands us
	d := newDeps(repo, tb, proxier)
	d.User = session.AdminUser
	d.IsAdmin = true

	done := make(chan int, 1)
	go func() { done <- session.Run(t.Context(), d) }()

	// "mw" is a subsequence of "mautrix-whatsapp" and of nothing else.
	go func() {
		_, _ = pw.Write([]byte("mw"))
		_, _ = pw.Write([]byte("\r"))
		for i := 0; i < 200; i++ {
			if len(proxierSessions(proxier)) > 0 {
				_ = pw.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the interactive picker hung")
	}

	sessions := proxierSessions(proxier)
	if len(sessions) != 1 {
		t.Fatalf("got %d console sessions, want 1", len(sessions))
	}
	if sessions[0].ProxmoxID != 101 {
		t.Errorf("connected to vmid %d, want 101 (the filtered guest)",
			sessions[0].ProxmoxID)
	}
}

// Ctrl+C must exit the picker cleanly without connecting anywhere.
func TestInteractivePickerQuitsOnCtrlC(t *testing.T) {
	repo := newRepo(t)
	seedGuest(t, repo)

	proxier := &testenv.MockProxier{}
	tb := newTerminal("\x03")
	tb.term.Raw = true
	d := newDeps(repo, tb, proxier)
	d.User = session.AdminUser
	d.IsAdmin = true

	if code := session.Run(t.Context(), d); code != 0 {
		t.Errorf("quitting must exit cleanly, got %d (stderr: %q)",
			code, tb.errb.String())
	}
	if len(proxier.Sessions) != 0 {
		t.Error("quitting must not open a console")
	}
}

// The picker's title must name the configured identity, not the login name
// the user typed.
//
// This goes through session.Run so it covers the wiring as well as the
// formatting: the title is built from Deps.DisplayName, which cmd/proxpass
// fills from Identity.DisplayName.
func TestPickerTitleNamesTheConfiguredIdentity(t *testing.T) {
	tests := []struct {
		name string
		raw  bool
	}{
		// Both renderers draw their own title, so each needs checking:
		// fixing one and leaving the other was the easy mistake here.
		{"interactive", true},
		{"numbered fallback", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo(t)
			seedGuest(t, repo)

			// Ctrl+C for the interactive picker, "q" for the numbered
			// prompt: the title is written before either is read, so the
			// input only needs to make the picker exit without connecting.
			input := "q\n"
			if tc.raw {
				input = "\x03"
			}
			tb := newTerminal(input)
			tb.term.Raw = tc.raw
			d := newDeps(repo, tb, &testenv.MockProxier{})
			// An admin logged in under a name of their choosing: the login
			// name is the alias, but the identity is the administrator.
			d.User = userAlias
			d.DisplayName = session.AdminUser
			d.IsAdmin = true

			_ = session.Run(t.Context(), d)

			out := tb.out.String()
			want := "guests available to " + session.AdminUser
			if !strings.Contains(out, want) {
				t.Errorf("title does not name the identity: want %q in %q", want, out)
			}
			if strings.Contains(out, "available to "+userAlias) {
				t.Errorf("the title echoed the login name back: %q", out)
			}
		})
	}
}

// A client's title must show the name the client was defined under.
//
// This is the case where DisplayName and the login name agree, so it guards
// the opposite failure from the test above: a fix that always printed
// "admin" would pass that one and break this.
func TestPickerTitleNamesTheClient(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	guest := seedGuest(t, repo)
	if err := repo.GrantClientAccess(
		t.Context(), client.ID, []int64{guest.ID}); err != nil {
		t.Fatalf("grant access: %v", err)
	}

	tb := newTerminal("\x03")
	tb.term.Raw = true
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.User = userAlice
	d.DisplayName = userAlice
	d.ClientID = client.ID

	_ = session.Run(t.Context(), d)

	if out := tb.out.String(); !strings.Contains(out, "guests available to "+userAlice) {
		t.Errorf("title does not name the client: %q", out)
	}
}

// Deps built without a DisplayName must still show a name rather than a
// blank, since the title is assembled from whatever the caller supplied.
func TestPickerTitleFallsBackToTheLoginName(t *testing.T) {
	repo := newRepo(t)
	seedGuest(t, repo)

	tb := newTerminal("\x03")
	tb.term.Raw = true
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.User = session.AdminUser
	d.IsAdmin = true
	// DisplayName deliberately left unset.

	_ = session.Run(t.Context(), d)

	if out := tb.out.String(); !strings.Contains(out, "guests available to "+session.AdminUser) {
		t.Errorf("title is missing a name entirely: %q", out)
	}
}

// The log must keep recording the login name that actually came in: it is
// the audit record of what was attempted, and the display name would hide a
// login under an unexpected alias.
func TestLogRecordsTheLoginNameNotTheDisplayName(t *testing.T) {
	repo := newRepo(t)
	seedGuest(t, repo)

	var logb bytes.Buffer
	tb := newTerminal("")
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.Logger = log.New(&logb, "", 0)
	d.User = userAlias
	d.DisplayName = session.AdminUser
	d.IsAdmin = true
	d.Command = cmdConnectCT100

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
	}
	if !strings.Contains(logb.String(), userAlias) {
		t.Errorf("the log does not record the login name: %q", logb.String())
	}
}

// The picker must leave the alternate screen and restore the cursor on every
// exit path, or the user is left staring at a blank terminal.
func TestInteractivePickerRestoresTheScreen(t *testing.T) {
	repo := newRepo(t)
	seedGuest(t, repo)

	tb := newTerminal("\x03")
	tb.term.Raw = true
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.User = session.AdminUser
	d.IsAdmin = true

	_ = session.Run(t.Context(), d)

	out := tb.out.String()
	if !strings.Contains(out, "\x1b[?1049h") {
		t.Error("the picker never entered the alternate screen")
	}
	if !strings.Contains(out, "\x1b[?1049l") {
		t.Error("the picker did not leave the alternate screen")
	}
	if !strings.Contains(out, "\x1b[?25h") {
		t.Error("the picker did not restore the cursor")
	}
}

// Without a PTY there is nothing to drive a full-screen UI, so the picker
// must fall back to the numbered prompt. Scripted use depends on it.
func TestPickerFallsBackToANumberedPromptWithoutAPTY(t *testing.T) {
	repo := newRepo(t)
	guest := seedGuest(t, repo)

	proxier := &testenv.MockProxier{}
	tb := newTerminal("1\n")
	tb.term.Raw = false // no PTY
	d := newDeps(repo, tb, proxier)
	d.User = session.AdminUser
	d.IsAdmin = true

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, tb.errb.String())
	}
	out := tb.out.String()
	if strings.Contains(out, "\x1b[?1049h") {
		t.Error("the fallback must not use the alternate screen")
	}
	if !strings.Contains(out, "Select a guest") {
		t.Errorf("output %q does not contain the numbered prompt", out)
	}
	sessions := proxierSessions(proxier)
	if len(sessions) != 1 || sessions[0].ProxmoxID != guest.ProxmoxID {
		t.Errorf("the numbered selection did not connect to the guest: %+v", sessions)
	}
}

// assertNoBareLF fails when s contains a newline that is not preceded by a
// carriage return. On a raw-mode PTY ONLCR is off, so such a newline moves
// the cursor down without returning it to column 0 and every subsequent line
// starts further right -- the staircase users reported.
func assertNoBareLF(t *testing.T, what, s string) {
	t.Helper()
	for i := 0; i < len(s); i++ {
		if s[i] != '\n' {
			continue
		}
		if i == 0 || s[i-1] != '\r' {
			t.Fatalf("%s contains a bare LF at offset %d, which staircases on a raw PTY: %q",
				what, i, s)
		}
	}
}

// Everything proxpass prints to a raw-mode terminal must be CRLF terminated.
// The numbered guest table was the worst offender: text/tabwriter emitted
// bare newlines and the list drifted further right with every row.
func TestSessionOutputIsCRLFOnRawTerminals(t *testing.T) {
	repo := newRepo(t)
	inst := &models.ProxmoxInstance{
		Name: instPVE, APIURL: pveAPIURL, Node: instPVE,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	for i, name := range []string{"alpha", "beta", "gamma"} {
		seedNamedGuest(t, repo, inst.ID, name, 100+i)
	}

	t.Run("help and guest table", func(t *testing.T) {
		client := addClient(t, repo)
		tb := newTerminal("")
		tb.term.Raw = true
		d := newDeps(repo, tb, &testenv.MockProxier{})
		d.User = userAlice
		d.ClientID = client.ID
		d.Command = "--help"

		if code := session.Run(t.Context(), d); code != 0 {
			t.Fatalf("help exit code = %d, want 0", code)
		}
		assertNoBareLF(t, "help output", tb.errb.String())
	})

	t.Run("error messages", func(t *testing.T) {
		tb := newTerminal("")
		tb.term.Raw = true
		d := newDeps(repo, tb, &testenv.MockProxier{})
		d.User = session.AdminUser
		d.IsAdmin = true
		d.Command = cmdConnectMissing

		if code := session.Run(t.Context(), d); code == 0 {
			t.Fatal("an unknown guest must fail")
		}
		assertNoBareLF(t, "error output", tb.errb.String())
	})

	// The connect banner announcing the Ctrl+A X escape prints immediately
	// before the guest takes over the terminal, so it has to be translated
	// like any other proxpass output.
	t.Run("connect banner", func(t *testing.T) {
		tb := newTerminal("")
		tb.term.Raw = true
		d := newDeps(repo, tb, &testenv.MockProxier{})
		d.User = session.AdminUser
		d.IsAdmin = true
		d.Command = cmdConnectCT100

		if code := session.Run(t.Context(), d); code != 0 {
			t.Fatalf("connect exit code = %d, want 0 (stderr %q)", code, tb.errb.String())
		}
		out := tb.out.String()
		// The escape hint is announced here only when no status bar will
		// carry it. This terminal is raw and tall, so the bar takes over
		// that job and the banner must not duplicate it.
		if console.WillDrawBar(tb.term) {
			if strings.Contains(out, console.EscapeHint) {
				t.Errorf("hint duplicated while a status bar is drawn: %q", out)
			}
		} else if !strings.Contains(out, console.EscapeHint) {
			t.Errorf("connect output does not announce the escape hatch: %q", out)
		}
		assertNoBareLF(t, "connect banner", out)
	})

	t.Run("admin CLI output", func(t *testing.T) {
		tb := newTerminal("")
		tb.term.Raw = true
		d := newDeps(repo, tb, &testenv.MockProxier{})
		d.User = session.AdminUser
		d.IsAdmin = true
		d.Command = cmdGuestLs

		if code := session.Run(t.Context(), d); code != 0 {
			t.Fatalf("%s exit code = %d, want 0 (stderr %q)", cmdGuestLs, code, tb.errb.String())
		}
		assertNoBareLF(t, cmdGuestLs+" output", tb.out.String())
	})

	t.Run("interactive picker frame", func(t *testing.T) {
		tb := newTerminal("\x03")
		tb.term.Raw = true
		d := newDeps(repo, tb, &testenv.MockProxier{})
		d.User = session.AdminUser
		d.IsAdmin = true

		_ = session.Run(t.Context(), d)
		assertNoBareLF(t, "picker frame", tb.out.String())
	})
}

// A cooked (non-raw) stream must NOT be given carriage returns: the terminal
// driver adds them itself, and a captured "guest ls --json" must stay valid.
func TestSessionOutputIsPlainOnCookedTerminals(t *testing.T) {
	repo := newRepo(t)
	tb := newTerminal("")
	tb.term.Raw = false
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.User = session.AdminUser
	d.IsAdmin = true
	d.Command = cmdGuestLs

	if code := session.Run(t.Context(), d); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.Contains(tb.out.String(), "\r") {
		t.Errorf("a cooked terminal must not receive carriage returns: %q",
			tb.out.String())
	}
}

// The admin CLI runs nested inside the "proxpass session" ucli command.
// urfave/cli stores the running command in the context and adopts it as the
// parent of any tree started with it, which sent help to Root().Writer --
// the OUTER root, which has no writer, so the text went straight to
// os.Stdout. It bypassed the session terminal entirely, which meant it
// skipped the raw-mode CRLF translation and staircased down the screen.
//
// A plain buffer cannot catch that, because the escape happens at the
// process level: this captures os.Stdout for the duration of the call.
func TestAdminHelpGoesToTheSessionTerminalNotStdout(t *testing.T) {
	realStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = realStdout })

	captured := make(chan string, 1)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		captured <- b.String()
	}()

	repo := newRepo(t)
	tb := newTerminal("")
	tb.term.Raw = true
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.User = session.AdminUser
	d.IsAdmin = true
	d.Command = "help"

	// The session must run with the context urfave/cli gives an Action, not
	// a bare one: that context carries the running command, and it is what
	// makes the nested admin CLI adopt it as a parent. Calling session.Run
	// with a plain context cannot reproduce the bug at all.
	outer := &ucli.Command{
		Name: "proxpass",
		Commands: []*ucli.Command{{
			Name: "session",
			Action: func(ctx context.Context, _ *ucli.Command) error {
				if code := session.Run(ctx, d); code != 0 {
					return fmt.Errorf("help exit code = %d, want 0", code)
				}
				return nil
			},
		}},
	}
	if err := outer.Run(t.Context(), []string{"proxpass", "session"}); err != nil {
		t.Fatalf("session: %v", err)
	}

	_ = w.Close()
	os.Stdout = realStdout
	leaked := <-captured

	if leaked != "" {
		t.Errorf("admin help leaked %d bytes to os.Stdout, bypassing the "+
			"session terminal and its CRLF translation: %q", len(leaked), leaked)
	}
	got := tb.errb.String()
	if !strings.Contains(got, "ProxPass admin CLI") {
		t.Fatalf("help did not reach the session terminal: %q", got)
	}
	assertNoBareLF(t, "admin help", got)

	// The usage line must name the command the user actually types, not the
	// internal nesting ("proxpass session proxpass ...").
	if strings.Contains(got, "session proxpass") {
		t.Errorf("usage line leaks the internal command nesting: %q", got)
	}
}

// A name proxpass would not serve as a login must be offered no keys.
//
// Note what this does NOT prove. sshd resolves the login through NSS before
// calling AuthorizedKeysCommand, and nss_http concatenates the name into its
// lookup URL unescaped, so "alice?x" is looked up as "alice" and sshd then
// uses that truncated name everywhere -- including the argv here. Logging the
// wrapper's argv in the image confirms it: `ssh 'a?b@host'` arrives as "a".
//
// So this guards the paths that pass a name through verbatim: a hand-run
// `proxpass authorized-keys`, and a future nss_http that escapes properly.
// The truncation itself is consistent across NSS, sshd and the session, so
// it yields a confusing alias rather than a privilege mismatch -- "alice?x"
// lands on the real client "alice" and gets only that client's keys.
func TestAuthorizedKeysRefusesUnservableNames(t *testing.T) {
	const adminKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF admin"
	repo := newRepo(t)

	for _, name := range []string{
		"alice?x",   // "?" starts the query: looked up as "alice"
		"alice#x",   // "#" starts the fragment: same
		"alice/x",   // adds a path segment
		"alice%2fx", // an escape the server decodes differently
		"alice:x",   // forges a passwd entry
		"-alice",    // parsed as a flag by AuthorizedKeysCommand
		"..",        // net/http redirects off the route
	} {
		var out bytes.Buffer
		if err := session.WriteAuthorizedKeys(
			t.Context(), &out, repo, name, adminKey); err != nil {
			t.Fatalf("name %q: WriteAuthorizedKeys: %v", name, err)
		}
		if out.Len() != 0 {
			t.Errorf("name %q was offered a key, so sshd would accept a login "+
				"whose uid belongs to a different identity: %q", name, out.String())
		}
		// The name is also refused at the session, so a hand-run
		// `proxpass session' cannot act on one either.
		if _, err := session.ResolveIdentityByKey(
			t.Context(), repo, name, writeAuthInfo(t, adminKey), adminKey,
		); err == nil {
			t.Errorf("name %q resolved to an identity, want it refused", name)
		}
	}
}

// The widened set must genuinely work: proxpass serves users over NSS, not
// from /etc/passwd, so it is not bound by useradd's policy.
func TestAuthorizedKeysAcceptsNamesUseraddWouldReject(t *testing.T) {
	const adminKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF admin"
	repo := newRepo(t)

	for _, name := range []string{"Tobias", "1st-box", "tobias.b", "tobías", "a@host"} {
		var out bytes.Buffer
		if err := session.WriteAuthorizedKeys(
			t.Context(), &out, repo, name, adminKey); err != nil {
			t.Fatalf("name %q: WriteAuthorizedKeys: %v", name, err)
		}
		if !strings.Contains(out.String(), adminKey) {
			t.Errorf("name %q was refused the admin key, but it is serviceable "+
				"over NSS", name)
		}
		id, err := session.ResolveIdentityByKey(
			t.Context(), repo, name, writeAuthInfo(t, adminKey), adminKey)
		if err != nil {
			t.Errorf("name %q: ResolveIdentityByKey: %v", name, err)
			continue
		}
		if !id.IsAdmin {
			t.Errorf("name %q did not resolve to the administrator", name)
		}
	}
}
