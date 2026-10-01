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

// Ctrl+A X must end the console even when the guest will not exit on its own.
//
// This is the whole point of the escape hatch, so the guest here ignores its
// stdin entirely: closing stdin is not enough to end it, and without the
// escape the session would hang until the client was killed externally.
func TestConnectSSHEscapeDisconnectsWedgedGuest(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()

	pt := newPipeTerminal()
	guest := &models.Guest{
		Type: models.GuestTypeCT, Name: guestWeb, ProxmoxID: testenv.WedgedVMID,
	}

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(
			pt.term, guest, sshInstance(t, mock), discardLogger())
	}()

	waitFor(t, pt.out, "entering LXC container")

	// Ordinary input reaches a wedged guest but cannot end it.
	if _, err := pt.stdin.Write([]byte("exit\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("console exited before the escape was sent: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	// Ctrl+A X must end it.
	if _, err := pt.stdin.Write([]byte{0x01, 'X'}); err != nil {
		t.Fatalf("write escape: %v", err)
	}

	select {
	case err := <-done:
		// A deliberate disconnect is a clean exit, not an error.
		if err != nil {
			t.Fatalf("Connect returned %v, want nil after Ctrl+A X", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Ctrl+A X did not disconnect the console")
	}
}

// The escape bytes must not reach the guest, which echoes what it receives.
func TestConnectSSHEscapeBytesDoNotReachTheGuest(t *testing.T) {
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
	before := pt.out.String()

	if _, err := pt.stdin.Write([]byte{0x01, 'X'}); err != nil {
		t.Fatalf("write escape: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Ctrl+A X did not disconnect the console")
	}

	// The mock echoes input, so an X arriving at the guest would come back.
	after := strings.TrimPrefix(pt.out.String(), before)
	if strings.ContainsAny(after, "\x01Xx") {
		t.Errorf("escape bytes were forwarded to the guest: %q", after)
	}
}

// A lone Ctrl+A is a real keystroke (start-of-line in a shell) and must still
// reach the guest rather than being held back or swallowed.
func TestConnectSSHForwardsLoneCtrlA(t *testing.T) {
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

	// Ctrl+A then a printable character: the mock echoes both.
	if _, err := pt.stdin.Write([]byte{0x01, 'z'}); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, pt.out, "\x01z")

	// The session must still be alive.
	select {
	case err := <-done:
		t.Fatalf("console exited on a lone Ctrl+A: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	_, _ = pt.stdin.Write([]byte{0x04})
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("console did not exit")
	}
}

// A status bar must reserve a row by requesting a shorter PTY and setting a
// scroll region, and must release both when a full-screen application takes
// over the screen.
func TestConnectSSHStatusBarYieldsToFullScreenApp(t *testing.T) {
	t.Setenv(console.DisableStatusBarEnv, "")
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()

	pt := newPipeTerminal()
	pt.term.Raw = true // a bar is only drawn on a raw PTY
	guest := &models.Guest{
		Type: models.GuestTypeCT, Name: guestWeb, ProxmoxID: testenv.AltScreenVMID,
	}

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(
			pt.term, guest, sshInstance(t, mock), discardLogger())
	}()

	// One row is reserved: 24 rows of terminal, 23 for the guest.
	waitFor(t, pt.out, "\x1b[1;23r")
	// The guest declared the alternate screen, so the region is released.
	waitFor(t, pt.out, "\x1b[r")

	// Leave the application, then the console.
	if _, err := pt.stdin.Write([]byte("q")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := pt.stdin.Write([]byte{0x01, 'X'}); err != nil {
		t.Fatalf("write escape: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("console did not exit")
	}
}

// With the bar disabled the guest must get the full terminal height and the
// terminal must see no scroll-region escapes at all.
func TestConnectSSHWithoutStatusBarLeavesTerminalAlone(t *testing.T) {
	t.Setenv(console.DisableStatusBarEnv, "1")
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()

	pt := newPipeTerminal()
	pt.term.Raw = true
	guest := &models.Guest{Type: models.GuestTypeCT, Name: guestWeb, ProxmoxID: 100}

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(
			pt.term, guest, sshInstance(t, mock), discardLogger())
	}()

	waitFor(t, pt.out, "root@CT100")
	_, _ = pt.stdin.Write([]byte{0x04})
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("console did not exit")
	}

	if got := pt.out.String(); strings.Contains(got, "\x1b[1;23r") {
		t.Errorf("a scroll region was installed even though the bar is disabled: %q", got)
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
