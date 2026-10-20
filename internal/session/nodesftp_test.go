package session_test

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"proxpass/internal/console"
	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/session"
	"proxpass/internal/testenv"
)

// scp and sftp to a NODE go through the node's own sftp subsystem: there is
// nothing to enter, so none of the guesthelper machinery is involved.

// sftpCommand is what sshd hands a ForceCommand for a transfer.
const sftpCommand = "/usr/lib/openssh/sftp-server"

// nodeOn builds an instance pointing at the mock SSH server and grants it
// to a fresh client, which it returns.
func nodeOn(t *testing.T, repo db.Repository, mock *testenv.MockSSHServer) *models.Client {
	t.Helper()
	inst := &models.ProxmoxInstance{
		Name: instRome, APIURL: romeAPIURL, Node: instRome,
		ConsoleTransport: models.ConsoleTransportSSH,
		SSHHost:          mock.Host, SSHPort: mock.Port, SSHUser: mock.User,
		SSHFingerprint: mock.HostKeyFingerprint(),
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	return grantNode(t, repo, inst.ID)
}

// pipeTerm wires the session's stdin/stdout to pipes, which a transfer
// needs: the protocol is a live conversation, not a canned script.
type pipeTerm struct {
	term    *console.Terminal
	toSess  *io.PipeWriter // test -> session stdin
	fromSes *io.PipeReader // session stdout -> test
}

func newPipeTerm() *pipeTerm {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	return &pipeTerm{
		term: &console.Terminal{
			In: inR, Out: outW, Err: io.Discard,
			Term: "xterm", Width: 80, Height: 24,
		},
		toSess:  inW,
		fromSes: outR,
	}
}

// Read and Write let an sftp client drive the session as one stream.
func (p *pipeTerm) Read(b []byte) (int, error)  { return p.fromSes.Read(b) }
func (p *pipeTerm) Write(b []byte) (int, error) { return p.toSess.Write(b) }
func (p *pipeTerm) Close() error {
	_ = p.toSess.Close()
	return p.fromSes.Close()
}

// A real sftp client, driven through proxpass, must reach the node's files.
//
// The point of the node path is that proxpass pumps bytes between an
// unmodified client and an unmodified sftp-server, so this uses the real
// pkg/sftp client against the mock's real pkg/sftp server. A test that
// spoke a simplified dialect would not be testing that.
func TestSFTPToANodeReachesItsFilesystem(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()
	root := t.TempDir()
	mock.SFTPRoot = root
	const want = "hello from the node\n"
	if err := os.WriteFile(filepath.Join(root, "motd"), []byte(want), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	// The API reads the deployment key and hands it to the session; point
	// it at the mock's so the dial succeeds.
	t.Setenv(models.SSHKeyPathEnv, mock.KeyPath)

	repo := newRepo(t)
	client := nodeOn(t, repo, mock)

	pt := newPipeTerm()
	d := &session.Deps{
		Repo:     repo,
		Logger:   log.New(io.Discard, "", 0),
		Terminal: pt.term,
	}
	d.LoginName = instRome
	d.IdentityName = userAlice
	d.ClientID = client.ID
	d.Command = sftpCommand
	d.Dir = &lazyAPIDirectory{deps: d}

	done := make(chan int, 1)
	go func() { done <- session.Run(t.Context(), d) }()

	sc, err := sftp.NewClientPipe(pt, pt)
	if err != nil {
		t.Fatalf("sftp handshake through proxpass failed: %v", err)
	}

	f, err := sc.Open(filepath.Join(root, "motd"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != want {
		t.Errorf("read %q, want %q", got, want)
	}

	// Writing too, since a transfer is usually the other direction.
	w, err := sc.Create(filepath.Join(root, "uploaded"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := w.Write([]byte("payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Close()
	_ = sc.Close()
	_ = pt.Close()

	onDisk, err := os.ReadFile(filepath.Join(root, "uploaded"))
	if err != nil {
		t.Fatalf("the upload did not reach the node: %v", err)
	}
	if string(onDisk) != "payload" {
		t.Errorf("uploaded %q, want %q", onDisk, "payload")
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the session did not exit after the transfer")
	}

	// It must have asked for "sftp" by NAME, not run a path as a command.
	if got := mock.Subsystems(); len(got) != 1 || got[0] != "sftp" {
		t.Errorf("subsystems requested = %v, want exactly [sftp]", got)
	}
}

// Binary content must survive the pump unchanged.
//
// This is what a PTY would break: a line discipline rewrites "\n" as
// "\r\n", so a file containing newline bytes would arrive corrupted.
func TestSFTPToANodeCarriesBinaryUnchanged(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()
	root := t.TempDir()
	mock.SFTPRoot = root

	// Every byte value, including \n, \r and NUL.
	payload := make([]byte, 256*4)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	t.Setenv(models.SSHKeyPathEnv, mock.KeyPath)

	repo := newRepo(t)
	client := nodeOn(t, repo, mock)

	pt := newPipeTerm()
	d := &session.Deps{Repo: repo, Logger: log.New(io.Discard, "", 0), Terminal: pt.term}
	d.LoginName = instRome
	d.IdentityName = userAlice
	d.ClientID = client.ID
	d.Command = sftpCommand
	d.Dir = &lazyAPIDirectory{deps: d}

	go func() { _ = session.Run(t.Context(), d) }()

	sc, err := sftp.NewClientPipe(pt, pt)
	if err != nil {
		t.Fatalf("sftp handshake: %v", err)
	}
	w, err := sc.Create(filepath.Join(root, "binary"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Close()
	_ = sc.Close()
	_ = pt.Close()

	got, err := os.ReadFile(filepath.Join(root, "binary"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("wrote %d bytes, read back %d: the stream was rewritten",
			len(payload), len(got))
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("byte %d is %#x, want %#x: the stream was rewritten",
				i, got[i], payload[i])
		}
	}
}

// A node the caller was not granted must not be transferable to.
//
// This exercises the SCOPING rather than the re-check inside
// serveNodeSFTP: namesANode consults AccessibleInstances, so an ungranted
// node is not a node at all and the name falls through to guest
// resolution, which also fails. The ConnectNode check is defense in depth,
// kept so that widening the scoping alone cannot open a hole -- which is
// why the log below reports "guest not found" rather than a node refusal.
func TestSFTPRefusesAnUngrantedNode(t *testing.T) {
	repo := newRepo(t)
	inst := seedNodeInstance(t, repo, instRome)
	// A client with no grant at all.
	c := &models.Client{Name: userAlice, PublicKeys: []string{aliceKey}}
	if err := repo.AddClient(t.Context(), c); err != nil {
		t.Fatalf("add client: %v", err)
	}
	stored, err := repo.GetClientByName(t.Context(), userAlice)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	_ = inst

	tb := newTerminal("")
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.LoginName = instRome
	d.IdentityName = userAlice
	d.ClientID = stored.ID
	d.Command = sftpCommand

	var logbuf strings.Builder
	d.Logger = log.New(&logbuf, "", 0)

	if code := session.Run(t.Context(), d); code == 0 {
		t.Error("exit = 0; a transfer reached a node that was never granted")
	}
	// And it never got as far as asking for credentials: the name stopped
	// resolving first.
	if strings.Contains(logbuf.String(), "sftp to node") {
		t.Errorf("an ungranted node was dialed anyway: %q", logbuf.String())
	}
}

// The reserved administrator name is not a transfer target, even when an
// instance bears it.
func TestSFTPRefusesTheReservedName(t *testing.T) {
	repo := newRepo(t)
	inst := seedNodeInstance(t, repo, adminName)
	grantNode(t, repo, inst.ID)

	tb := newTerminal("")
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.LoginName = adminName
	d.IsAdmin = true
	d.Command = sftpCommand

	if code := session.Run(t.Context(), d); code == 0 {
		t.Error("exit = 0; `admin' is reserved and names no transfer target")
	}
}

// A guest transfer still resolves to the guest, not to its node.
//
// The node check sits in front of guest resolution, so this is the case
// that would break if it matched too eagerly.
func TestSFTPToAGuestIsUnaffected(t *testing.T) {
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

	tb := newTerminal("")
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.LoginName = guestWeb
	d.IdentityName = userAlice
	d.ClientID = client.ID
	d.Command = sftpCommand

	// It fails -- the fixture node is not dialable -- but the LOG says
	// which path it took, which is what this asserts.
	var logbuf strings.Builder
	d.Logger = log.New(&logbuf, "", 0)
	session.Run(t.Context(), d)

	if strings.Contains(logbuf.String(), "sftp to node") {
		t.Errorf("a guest name routed to the node transfer: %q", logbuf.String())
	}
}
