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
	userAlice  = "alice"
	guestCT100 = "ct100"
	pveAPIURL  = "https://pve:8006"
	instPVE    = "pve"
	cmdGuestLs = "guest ls"
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

// A client must never be offered the admin key.
func TestAuthorizedKeysFlagKeyIsAdminOnly(t *testing.T) {
	repo := newRepo(t)
	addClient(t, repo, "ssh-ed25519 AAAAalice alice")
	const flagKey = "ssh-ed25519 AAAAflag admin"

	var out bytes.Buffer
	_ = session.WriteAuthorizedKeys(t.Context(), &out, repo, userAlice, flagKey)
	if strings.Contains(out.String(), flagKey) {
		t.Error("client was offered the admin key")
	}
}

// --- identity ----------------------------------------------------------

func TestResolveIdentityAdmin(t *testing.T) {
	repo := newRepo(t)
	id, err := session.ResolveIdentity(t.Context(), repo, session.AdminUser)
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	if !id.IsAdmin {
		t.Error("admin user must resolve to an admin identity")
	}
}

func TestResolveIdentityClient(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)

	id, err := session.ResolveIdentity(t.Context(), repo, userAlice)
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	if id.IsAdmin {
		t.Error("client must not be an admin")
	}
	if id.ClientID != client.ID {
		t.Errorf("ClientID = %d, want %d", id.ClientID, client.ID)
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

	if _, err := session.ResolveIdentity(t.Context(), repo, session.AdminUser); err == nil {
		t.Fatal("a client shadowing the admin login must be refused")
	}
}

// Even with such a client present, its keys must never be offered for the
// admin login.
func TestAuthorizedKeysNeverOffersAShadowedAdminClientKey(t *testing.T) {
	repo := newRepo(t)
	const attacker = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF attacker"
	if err := repo.AddClient(t.Context(), &models.Client{
		Name: session.AdminUser, PublicKeys: []string{attacker},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}

	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(
		t.Context(), &out, repo, session.AdminUser, ""); err != nil {
		t.Fatalf("WriteAuthorizedKeys: %v", err)
	}
	if strings.Contains(out.String(), "attacker") {
		t.Errorf("the shadowing client's key was offered for the admin login: %q", out.String())
	}
}

// A login name that is not a client belongs to the administrator.
//
// sshd has already authenticated it against the admin key list by the time
// this runs: WriteAuthorizedKeys offers only admin keys for such a name. This
// restores the behavior proxpass had with its own SSH server, where the key
// authenticated the connection and the login name was cosmetic.
func TestResolveIdentityTreatsANonClientNameAsTheAdmin(t *testing.T) {
	repo := newRepo(t)
	id, err := session.ResolveIdentity(t.Context(), repo, "tobias")
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	if !id.IsAdmin {
		t.Error("a non-client login name must resolve to the administrator")
	}
	if id.User != "tobias" {
		t.Errorf("User = %q, want %q", id.User, "tobias")
	}
	if id.ClientID != 0 {
		t.Errorf("ClientID = %d, want 0", id.ClientID)
	}
}

// Only admin keys may be offered for a name that is not a client: a client's
// key must never authorize an admin alias.
func TestAuthorizedKeysOffersOnlyAdminKeysForANonClientName(t *testing.T) {
	const (
		adminKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF admin"
		clientKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHixnSBaUZmAX3Qd4hYl71jjgr58KXAJTdKjFrax6FHN alice"
	)
	repo := newRepo(t)
	addClient(t, repo, clientKey)

	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(
		t.Context(), &out, repo, "tobias", adminKey); err != nil {
		t.Fatalf("WriteAuthorizedKeys: %v", err)
	}
	if !strings.Contains(out.String(), adminKey) {
		t.Errorf("the admin key was not offered for an alias: %q", out.String())
	}
	if strings.Contains(out.String(), clientKey) {
		t.Errorf("a client's key was offered for an alias: %q", out.String())
	}
}

// A client name must still resolve to that client, and must not be promoted
// to an administrator.
func TestAuthorizedKeysNeverOffersAnAdminKeyForAClient(t *testing.T) {
	const (
		adminKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF admin"
		clientKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHixnSBaUZmAX3Qd4hYl71jjgr58KXAJTdKjFrax6FHN alice"
	)
	repo := newRepo(t)
	addClient(t, repo, clientKey)

	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(
		t.Context(), &out, repo, userAlice, adminKey); err != nil {
		t.Fatalf("WriteAuthorizedKeys: %v", err)
	}
	if strings.Contains(out.String(), adminKey) {
		t.Errorf("an admin key was offered for a client login: %q", out.String())
	}

	id, err := session.ResolveIdentity(t.Context(), repo, userAlice)
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
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
	return &session.Deps{
		Repo:     repo,
		Proxier:  proxier,
		Logger:   log.New(io.Discard, "", 0),
		Terminal: tb.term,
	}
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
		Type: models.GuestTypeCT, Name: "web", Status: models.StatusRunning,
		ProxmoxID: 100, InstanceID: inst.ID,
	}
	if err := repo.UpsertGuest(t.Context(), guest); err != nil {
		t.Fatalf("upsert guest: %v", err)
	}
	guests, _ := repo.ListGuests(t.Context())
	return guests[0]
}

// A client must not be able to reach the admin CLI by passing a multi-word
// command.
func TestClientCannotRunAdminCommands(t *testing.T) {
	repo := newRepo(t)
	client := addClient(t, repo)
	tb := newTerminal("")

	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.User = userAlice
	d.ClientID = client.ID
	d.Command = cmdGuestLs

	if code := session.Run(t.Context(), d); code == 0 {
		t.Error("multi-word command from a client must fail")
	}
	if !strings.Contains(tb.errb.String(), "access denied") {
		t.Errorf("stderr = %q, want an access denied message", tb.errb.String())
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
	d.Command = guestCT100

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
	d.Command = guestCT100

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
	d.Command = guestCT100

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
	d.Command = "ct999"

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
		d.Command = "ct999"

		if code := session.Run(t.Context(), d); code == 0 {
			t.Fatal("an unknown guest must fail")
		}
		assertNoBareLF(t, "error output", tb.errb.String())
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
