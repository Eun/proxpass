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
	mockTokenID     = "root@pam!test"
	mockTokenSecret = "00000000-0000-0000-0000-000000000000"

	nodePVE   = "pve"
	guestWeb  = "web"
	stRunning = "running"
)

// termProxyEnv starts a mock Proxmox API with one container registered and a
// termproxy ticket ready for it.
func termProxyEnv(t *testing.T) (*testenv.MockAPIServer, *models.ProxmoxInstance, *models.Guest) {
	t.Helper()

	api := testenv.NewMockAPIServer(mockTokenID, mockTokenSecret)
	t.Cleanup(api.Close)

	api.SetLocalNode(nodePVE)
	api.AddLXC(nodePVE, 100, guestWeb, stRunning)
	api.AddTermProxy(nodePVE, "lxc", 100, "TICKET", 5900)
	api.SetTermProxyGreeting("root@CT100:~# ")

	inst := &models.ProxmoxInstance{
		Name:           nodePVE,
		APIURL:         api.URL(),
		APITokenID:     mockTokenID,
		APITokenSecret: mockTokenSecret,
		ConnectionType: models.ConnectionTypeTermProxy,
		Node:           nodePVE,
	}
	guest := &models.Guest{
		Type: models.GuestTypeCT, Name: guestWeb, Status: models.StatusRunning,
		ProxmoxID: 100,
	}
	return api, inst, guest
}

// The termproxy transport must complete the handshake and stream the guest's
// output back to the terminal.
func TestConnectTermProxyHandshake(t *testing.T) {
	api, inst, guest := termProxyEnv(t)
	pt := newPipeTerminal()

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(pt.term, guest, inst, "", discardLogger())
	}()

	waitFor(t, pt.out, "root@CT100")

	// The client authenticates with "<authid>:<ticket>".
	if got := api.TermProxy().AuthLine(); got != mockTokenID+":TICKET" {
		t.Errorf("auth line = %q, want %q", got, mockTokenID+":TICKET")
	}

	_ = pt.stdin.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("termproxy session did not end after stdin closed")
	}
}

// Keystrokes must be framed as "0:<len>:<data>" and arrive intact.
func TestConnectTermProxyForwardsInput(t *testing.T) {
	api, inst, guest := termProxyEnv(t)
	pt := newPipeTerminal()

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(pt.term, guest, inst, "", discardLogger())
	}()

	waitFor(t, pt.out, "root@CT100")
	if _, err := pt.stdin.Write([]byte("uptime\r")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The mock echoes the payload back unframed.
	waitFor(t, pt.out, "uptime")

	if got := api.TermProxy().Input(); !strings.Contains(got, "uptime") {
		t.Errorf("guest received %q, want it to contain \"uptime\"", got)
	}

	_ = pt.stdin.Close()
	<-done
}

// Non-ASCII input must survive framing. Building the frame by formatting the
// payload through a string would corrupt these bytes and desynchronise the
// declared length from the data.
func TestConnectTermProxyForwardsBinaryInput(t *testing.T) {
	api, inst, guest := termProxyEnv(t)
	pt := newPipeTerminal()

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(pt.term, guest, inst, "", discardLogger())
	}()
	waitFor(t, pt.out, "root@CT100")

	// An up-arrow escape sequence plus a multi-byte rune.
	payload := "\x1b[A€"
	if _, err := pt.stdin.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(api.TermProxy().Input(), payload) {
			_ = pt.stdin.Close()
			<-done
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("guest received %q, want it to contain %q",
		api.TermProxy().Input(), payload)
}

// A resize must be sent as "1:<cols>:<rows>:".
func TestConnectTermProxyForwardsResize(t *testing.T) {
	api, inst, guest := termProxyEnv(t)
	pt := newPipeTerminal()

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(pt.term, guest, inst, "", discardLogger())
	}()
	waitFor(t, pt.out, "root@CT100")

	pt.resizes <- console.Size{Width: 120, Height: 40}
	waitFor(t, pt.out, "[resized 120x40]")

	got := api.TermProxy().Resizes()
	if len(got) == 0 || got[len(got)-1] != [2]int{120, 40} {
		t.Errorf("resizes = %v, want the last to be [120 40]", got)
	}

	_ = pt.stdin.Close()
	<-done
}

// The initial terminal size must be sent before any input, so the guest
// starts with the right geometry.
func TestConnectTermProxySendsInitialSize(t *testing.T) {
	api, inst, guest := termProxyEnv(t)
	pt := newPipeTerminal()
	pt.term.Width, pt.term.Height = 100, 30

	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(pt.term, guest, inst, "", discardLogger())
	}()
	waitFor(t, pt.out, "root@CT100")

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got := api.TermProxy().Resizes(); len(got) > 0 && got[0] == [2]int{100, 30} {
			_ = pt.stdin.Close()
			<-done
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("initial resize = %v, want [100 30] first", api.TermProxy().Resizes())
}

// A VM uses the qemu path rather than lxc.
func TestConnectTermProxyToVM(t *testing.T) {
	api := testenv.NewMockAPIServer(mockTokenID, mockTokenSecret)
	t.Cleanup(api.Close)
	api.SetLocalNode(nodePVE)
	api.AddQEMU(nodePVE, 200, "db", stRunning)
	api.AddTermProxy(nodePVE, "qemu", 200, "VMTICKET", 5901)
	api.SetTermProxyGreeting("login: ")

	inst := &models.ProxmoxInstance{
		Name: nodePVE, APIURL: api.URL(),
		APITokenID: mockTokenID, APITokenSecret: mockTokenSecret,
		ConnectionType: models.ConnectionTypeTermProxy, Node: nodePVE,
	}
	guest := &models.Guest{Type: models.GuestTypeVM, Name: "db", ProxmoxID: 200}

	pt := newPipeTerminal()
	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(pt.term, guest, inst, "", discardLogger())
	}()

	waitFor(t, pt.out, "login:")
	if got := api.TermProxy().AuthLine(); !strings.HasSuffix(got, ":VMTICKET") {
		t.Errorf("auth line = %q, want it to end with the VM ticket", got)
	}

	_ = pt.stdin.Close()
	<-done
}

// A guest with no termproxy ticket must fail rather than hang.
func TestConnectTermProxyTicketFailure(t *testing.T) {
	api := testenv.NewMockAPIServer(mockTokenID, mockTokenSecret)
	t.Cleanup(api.Close)
	api.SetLocalNode(nodePVE)
	api.AddLXC(nodePVE, 100, guestWeb, stRunning)
	// Deliberately no AddTermProxy.

	inst := &models.ProxmoxInstance{
		Name: nodePVE, APIURL: api.URL(),
		APITokenID: mockTokenID, APITokenSecret: mockTokenSecret,
		ConnectionType: models.ConnectionTypeTermProxy, Node: nodePVE,
	}
	guest := &models.Guest{Type: models.GuestTypeCT, Name: guestWeb, ProxmoxID: 100}

	pt := newPipeTerminal()
	errCh := make(chan error, 1)
	go func() {
		errCh <- console.DefaultProxier{}.Connect(pt.term, guest, inst, "", discardLogger())
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("a missing termproxy ticket must fail")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Connect hung when the ticket could not be created")
	}
}

// Bad credentials must be reported rather than silently retried.
func TestConnectTermProxyRejectsBadToken(t *testing.T) {
	api, inst, guest := termProxyEnv(t)
	_ = api
	inst.APITokenSecret = "wrong-secret"

	pt := newPipeTerminal()
	errCh := make(chan error, 1)
	go func() {
		errCh <- console.DefaultProxier{}.Connect(pt.term, guest, inst, "", discardLogger())
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("a bad API token must fail")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Connect hung on a bad API token")
	}
}

// An unknown guest type has no termproxy path.
func TestConnectTermProxyUnknownGuestType(t *testing.T) {
	_, inst, _ := termProxyEnv(t)
	guest := &models.Guest{Type: models.GuestType("bogus"), Name: "x", ProxmoxID: 1}

	pt := newPipeTerminal()
	if err := (console.DefaultProxier{}).Connect(
		pt.term, guest, inst, "", discardLogger()); err == nil {
		t.Fatal("an unknown guest type must be rejected")
	}
}
