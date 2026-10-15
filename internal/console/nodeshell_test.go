package console_test

import (
	"strings"
	"testing"
	"time"

	"proxpass/internal/console"
	"proxpass/internal/models"
	"proxpass/internal/testenv"
)

const (
	loopbackHost = "127.0.0.1"
	nodeUser     = "root"
)

// A node shell is a plain interactive shell on the Proxmox host.
//
// The distinction that matters: a GUEST console sends an "exec" request
// carrying `pct enter' or `qm terminal', while a node sends "shell" and
// lets the remote end start the login shell. The mock answers the two
// differently, so the banner says which request actually went out.

func TestConnectNodeOpensAShellNotAGuestConsole(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()

	pt := newPipeTerminal()

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.ConnectNode(
			pt.term, sshInstance(t, mock), sshKeyOf(t, mock), discardLogger())
	}()

	waitFor(t, pt.out, "interactive shell")

	// Ctrl+D ends the mock session, which must end the console cleanly.
	_, _ = pt.stdin.Write([]byte{0x04})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ConnectNode returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the node console did not exit after the session ended")
	}

	got := pt.out.String()
	// The guest commands must not appear: a node shell enters nothing.
	for _, guestCmd := range []string{"entering LXC container", "starting serial terminal"} {
		if strings.Contains(got, guestCmd) {
			t.Errorf("a node shell ran a GUEST console command (%q): %q", guestCmd, got)
		}
	}
}

// Input reaches the node and comes back, so the shell is really attached.
func TestConnectNodeForwardsInput(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()

	pt := newPipeTerminal()

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.ConnectNode(
			pt.term, sshInstance(t, mock), sshKeyOf(t, mock), discardLogger())
	}()

	waitFor(t, pt.out, "interactive shell")
	_, _ = pt.stdin.Write([]byte("uptime\n"))
	waitFor(t, pt.out, "uptime")

	_, _ = pt.stdin.Write([]byte{0x04})
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the node console did not exit")
	}
}

// An unreachable node reports an error rather than hanging or panicking.
func TestConnectNodeUnreachableHost(t *testing.T) {
	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	// Read the key BEFORE closing: Close removes the temp key file.
	keyPEM := sshKeyOf(t, mock)
	port := mock.Port
	mock.Close() // nothing is listening any more

	inst := &models.ProxmoxInstance{
		Name:             nodePVE,
		ConsoleTransport: models.ConsoleTransportSSH,
		SSHHost:          loopbackHost,
		SSHPort:          port,
		SSHUser:          nodeUser,
	}
	pt := newPipeTerminal()

	errCh := make(chan error, 1)
	go func() {
		errCh <- console.DefaultProxier{}.ConnectNode(pt.term, inst, keyPEM, discardLogger())
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("connecting to an unreachable node returned no error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("connecting to an unreachable node hung")
	}
}
