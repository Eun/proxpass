package console_test

import (
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"proxpass/internal/console"
	"proxpass/internal/models"
	"proxpass/internal/testenv"
)

// pipeTerminal is a console.Terminal whose input is driven by the test and
// whose output is captured, standing in for the PTY sshd would provide.
type pipeTerminal struct {
	term    *console.Terminal
	stdin   *io.PipeWriter
	out     *syncBuffer
	errOut  *syncBuffer
	resizes chan console.Size
}

func newPipeTerminal() *pipeTerminal {
	pr, pw := io.Pipe()
	out := &syncBuffer{}
	errOut := &syncBuffer{}
	resizes := make(chan console.Size, 4)
	return &pipeTerminal{
		term: &console.Terminal{
			In:      pr,
			Out:     out,
			Err:     errOut,
			Term:    "xterm-256color",
			Width:   80,
			Height:  24,
			Resizes: resizes,
		},
		stdin:   pw,
		out:     out,
		errOut:  errOut,
		resizes: resizes,
	}
}

// sshInstance points at the mock Proxmox host.
func sshInstance(t *testing.T, mock *testenv.MockSSHServer) *models.ProxmoxInstance {
	t.Helper()
	return &models.ProxmoxInstance{
		Name:           nodePVE,
		ConnectionType: models.ConnectionTypeSSH,
		SSHHost:        mock.Host,
		SSHPort:        mock.Port,
		SSHUser:        mock.User,
		SSHKeyPath:     mock.KeyPath,
	}
}

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// A container console must run "pct enter <vmid>" on the Proxmox host and
// bridge its output back to the terminal.
func TestConnectSSHToContainer(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()

	pt := newPipeTerminal()
	guest := &models.Guest{Type: models.GuestTypeCT, Name: guestWeb, ProxmoxID: 100}

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(
			pt.term, guest, sshInstance(t, mock), discardLogger())
	}()

	waitFor(t, pt.out, "entering LXC container 100")

	// Ctrl+D ends the mock session, which must end the console cleanly.
	_, _ = pt.stdin.Write([]byte{0x04})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Connect returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("console did not exit after the guest session ended")
	}

	if got := pt.out.String(); !strings.Contains(got, "root@CT100") {
		t.Errorf("terminal output does not look like a container console: %q", got)
	}
}

// A VM console must run "qm terminal <vmid>" instead.
func TestConnectSSHToVM(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()

	pt := newPipeTerminal()
	guest := &models.Guest{Type: models.GuestTypeVM, Name: "db", ProxmoxID: 200}

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(
			pt.term, guest, sshInstance(t, mock), discardLogger())
	}()

	waitFor(t, pt.out, "starting serial terminal on VM 200")

	_ = pt.stdin.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("console did not exit after stdin closed")
	}
}

// Input typed at the terminal must reach the guest: the mock echoes it back.
func TestConnectSSHForwardsInput(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()

	pt := newPipeTerminal()
	guest := &models.Guest{Type: models.GuestTypeCT, Name: guestWeb, ProxmoxID: 100}

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(
			pt.term, guest, sshInstance(t, mock), discardLogger())
	}()

	waitFor(t, pt.out, "root@CT100")
	if _, err := pt.stdin.Write([]byte("hello")); err != nil {
		t.Fatalf("write to terminal: %v", err)
	}
	waitFor(t, pt.out, "hello")

	_, _ = pt.stdin.Write([]byte{0x04})
	<-done
}

// Resizing the local terminal must not disturb the session. The SSH transport
// forwards it as a window-change request.
func TestConnectSSHHandlesResize(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()

	pt := newPipeTerminal()
	guest := &models.Guest{Type: models.GuestTypeCT, Name: guestWeb, ProxmoxID: 100}

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(
			pt.term, guest, sshInstance(t, mock), discardLogger())
	}()

	waitFor(t, pt.out, "root@CT100")
	pt.resizes <- console.Size{Width: 120, Height: 40}

	// The session must still be usable afterwards.
	if _, err := pt.stdin.Write([]byte("after-resize")); err != nil {
		t.Fatalf("write after resize: %v", err)
	}
	waitFor(t, pt.out, "after-resize")

	_, _ = pt.stdin.Write([]byte{0x04})
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("console did not exit after a resize")
	}
}

// An unreachable Proxmox host must surface an error rather than hanging.
func TestConnectSSHUnreachableHost(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	keyPath := mock.KeyPath
	port := mock.Port
	mock.Close() // nothing is listening any more

	inst := &models.ProxmoxInstance{
		Name:           nodePVE,
		ConnectionType: models.ConnectionTypeSSH,
		SSHHost:        "127.0.0.1",
		SSHPort:        port,
		SSHUser:        "root",
		SSHKeyPath:     keyPath,
	}
	pt := newPipeTerminal()
	guest := &models.Guest{Type: models.GuestTypeCT, Name: guestWeb, ProxmoxID: 100}

	errCh := make(chan error, 1)
	go func() {
		errCh <- console.DefaultProxier{}.Connect(pt.term, guest, inst, discardLogger())
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("connecting to a dead host must fail")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Connect hung against an unreachable host")
	}
}

// A missing key file must be reported, not panic.
func TestConnectSSHMissingKey(t *testing.T) {
	inst := &models.ProxmoxInstance{
		Name:           nodePVE,
		ConnectionType: models.ConnectionTypeSSH,
		SSHHost:        "127.0.0.1",
		SSHPort:        1,
		SSHUser:        "root",
		SSHKeyPath:     "/nonexistent/key",
	}
	pt := newPipeTerminal()
	guest := &models.Guest{Type: models.GuestTypeCT, Name: guestWeb, ProxmoxID: 100}

	if err := (console.DefaultProxier{}).Connect(
		pt.term, guest, inst, discardLogger()); err == nil {
		t.Fatal("a missing key file must be reported")
	}
}

// An unknown guest type has no console command and must be rejected before
// any connection is attempted.
func TestConnectSSHUnknownGuestType(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()

	pt := newPipeTerminal()
	guest := &models.Guest{Type: models.GuestType("bogus"), Name: "x", ProxmoxID: 1}

	if err := (console.DefaultProxier{}).Connect(
		pt.term, guest, sshInstance(t, mock), discardLogger()); err == nil {
		t.Fatal("an unknown guest type must be rejected")
	}
}
