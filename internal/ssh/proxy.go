package ssh

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/tui"

	gossh "golang.org/x/crypto/ssh"
)

// SSH channel request type constants.
const (
	reqTypePTY       = "pty-req"
	reqTypeShell     = "shell"
	reqTypeExec      = "exec"
	reqTypeWinChange = "window-change"
)

const (
	termXterm         = "xterm"
	termXterm256Color = "xterm-256color"
)

// GuestNotFoundError is returned when a guest identifier cannot be resolved.
type GuestNotFoundError struct { GuestName string }

func (e *GuestNotFoundError) Error() string {
	return fmt.Sprintf("guest %q not found", e.GuestName)
}
func (e *GuestNotFoundError) Is(err error) bool {
	_, ok := err.(*GuestNotFoundError)
	return ok
}

// isHelpCommand returns true if the command should be routed to usage output.
func isHelpCommand(cmd string) bool {
	for _, v := range []string{"help", "--help", "-h"} {
		if strings.EqualFold(cmd, v) {
			return true
		}
	}
	return false
}

// splitArgs does a simple shell-like split (double-quote aware).
func splitArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}

// interactiveGuestPicker shows the TUI picker and proxies to the selected
// guest. clientID==0 means admin (show all); clientID>0 filters by access.
func interactiveGuestPicker(
	ctx context.Context,
	clientID int64,
	channel gossh.Channel,
	remaining <-chan *gossh.Request,
	repo db.Repository,
	proxier GuestProxier,
	ptyReq *PtyRequest,
	logger *log.Logger,
) {
	label := labelFromClientID(clientID)

	guests, err := repo.ListGuests(ctx)
	if err != nil {
		logger.Printf("%s: list guests for picker: %v", label, err)
		writeErr(channel, ptyReq, "internal error")
		drainAndDiscard(remaining)
		return
	}

	if clientID != 0 {
		guests = filterByAccess(ctx, guests, clientID, repo, channel, ptyReq, remaining)
		if guests == nil {
			return // error already written
		}
	}

	if len(guests) == 0 {
		_, _ = fmt.Fprintf(newCRLFWriter(channel.Stderr()), "\r\nNo guests discovered.\r\n")
		drainAndDiscard(remaining)
		return
	}

	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		logger.Printf("%s: list instances for picker: %v", label, err)
		writeErr(channel, ptyReq, "internal error")
		drainAndDiscard(remaining)
		return
	}

	instMap := make(map[int64]string, len(instances))
	instByID := make(map[int64]*models.ProxmoxInstance, len(instances))
	for _, inst := range instances {
		instMap[inst.ID] = inst.Name
		instByID[inst.ID] = inst
	}

	drainAndDiscard(remaining)

	guest, _, pickErr := tui.PickGuest(channel, channel, guests, instMap, ptyReq.Width, ptyReq.Height, ptyReq.Term)
	if pickErr != nil {
		logger.Printf("%s: picker error: %v", label, pickErr)
		return
	}
	if guest == nil {
		return // user cancelled
	}

	inst := instByID[guest.InstanceID]
	if inst == nil {
		writeErr(channel, ptyReq, fmt.Sprintf("instance for guest %q not found", guest.Name))
		return
	}
	printConnectionBanner(channel, guest, inst)

	proxyReqs := make(chan *gossh.Request, 4)
	defer close(proxyReqs)
	if err := proxier.ProxyToGuest(channel, proxyReqs, guest, inst, ptyReq, logger); err != nil {
		logger.Printf("%s: proxy error: %v", label, err)
	}
}

// filterByAccess removes guests the client cannot access.
// Returns nil (and writes the error) if a repo call fails.
func filterByAccess(
	ctx context.Context,
	guests []*models.Guest,
	clientID int64,
	repo db.Repository,
	channel gossh.Channel,
	ptyReq *PtyRequest,
	remaining <-chan *gossh.Request,
) []*models.Guest {
	for i := len(guests) - 1; i >= 0; i-- {
		ok, err := repo.HasAccess(ctx, clientID, guests[i].ID)
		if err != nil {
			writeErr(channel, ptyReq, fmt.Sprintf("Error: %v", err))
			drainAndDiscard(remaining)
			return nil
		}
		if !ok {
			guests = append(guests[:i], guests[i+1:]...)
		}
	}
	return guests
}

// labelFromClientID returns a log-friendly label for an access ID.
func labelFromClientID(clientID int64) string {
	if clientID == 0 {
		return "admin"
	}
	return fmt.Sprintf("client/%d", clientID)
}

// ctrlAXReader wraps an io.Reader and cancels the provided cancel function
// when the byte sequence Ctrl+A (0x01) followed by X is detected in the stream.
// This gives users a reliable escape hatch to terminate a guest console session
// without killing the SSH connection itself.
type ctrlAXReader struct {
	r      io.Reader
	cancel context.CancelFunc
	pending bool // true when we have seen 0x01 and are waiting for the next byte
}

func (c *ctrlAXReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	for i := 0; i < n; i++ {
		switch {
		case c.pending:
			c.pending = false
			if p[i] == 'X' || p[i] == 'x' {
				// Signal termination and return EOF with zero bytes so that
				// neither the 0x01 nor the X reaches the guest. We do not
				// attempt to splice the bytes out of p because 0x01 may have
				// been at index 0 of this call (making p[i-1] invalid) or
				// even arrived in a previous Read call (already returned).
				c.cancel()
				return 0, io.EOF
			}
		case p[i] == 0x01: // Ctrl+A
			c.pending = true
		}
	}
	return n, err
}

// proxyToGuest connects to the Proxmox host via SSH and bidirectionally
// forwards data between the SSH channel and the guest console.
//
//nolint:gocognit // SSH proxy requires sequential setup of pipes, goroutines, and teardown
func proxyToGuest(
	clientChan gossh.Channel,
	clientReqs <-chan *gossh.Request,
	guest *models.Guest,
	inst *models.ProxmoxInstance,
	ptyReq *PtyRequest,
	logger *log.Logger,
) error {
	keyBytes, err := loadInstanceKey(inst)
	if err != nil {
		return err
	}
	signer, err := gossh.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("parsing proxmox key: %w", err)
	}

	addr := net.JoinHostPort(inst.SSHHost, strconv.Itoa(inst.SSHPort))
	remote, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            inst.SSHUser,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // Proxmox host verification is out of scope.
	})
	if err != nil {
		return fmt.Errorf("dialing proxmox %s: %w", addr, err)
	}
	defer func() { _ = remote.Close() }()

	session, err := remote.NewSession()
	if err != nil {
		return fmt.Errorf("opening remote session: %w", err)
	}
	defer func() { _ = session.Close() }()

	if err := session.RequestPty(effectivePty(ptyReq)); err != nil {
		return fmt.Errorf("requesting remote pty: %w", err)
	}

	cmd, err := guestConsoleCmd(guest)
	if err != nil {
		return err
	}

	remoteStdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	remoteStdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	remoteStderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("starting command %q: %w", cmd, err)
	}

	ctrlCtx, ctrlCancel := context.WithCancel(context.Background())
	defer ctrlCancel()

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Forward window-change requests from the client to the remote session.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			case req, ok := <-clientReqs:
				if !ok {
					return
				}
				if req.Type == reqTypeWinChange {
					if w, h, pErr := parseWindowChange(req.Payload); pErr == nil {
						_ = session.WindowChange(int(h), int(w))
					}
				}
				replyReq(req, false)
			}
		}
	}()

	// client → remote stdin, with Ctrl+A X hotkey interception.
	go func() {
		src := &ctrlAXReader{r: clientChan, cancel: ctrlCancel}
		_, _ = io.Copy(remoteStdin, src)
		_ = remoteStdin.Close()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientChan, remoteStdout)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientChan.Stderr(), remoteStderr)
	}()

	// Wait for either the remote session to finish or Ctrl+A X to be pressed.
	go func() {
		<-ctrlCtx.Done()
		if logger != nil {
			logger.Print("proxyToGuest: Ctrl+A X received; terminating session")
		}
		_ = session.Signal(gossh.SIGTERM)
		_ = session.Close()
	}()

	err = session.Wait()
	close(done)
	_ = remoteStdin.Close()
	wg.Wait()
	// If the session ended due to Ctrl+A X, that is a clean exit.
	if ctrlCtx.Err() != nil {
		return nil
	}
	return err
}

// loadInstanceKey returns the PEM private key bytes for a Proxmox instance.
// Inline Key (in DB) takes precedence over KeyPath (file on disk).
func loadInstanceKey(inst *models.ProxmoxInstance) ([]byte, error) {
	if inst.SSHKey != "" {
		return []byte(inst.SSHKey), nil
	}
	b, err := os.ReadFile(inst.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading proxmox key %s: %w", inst.SSHKeyPath, err)
	}
	return b, nil
}

// effectivePty returns the PTY parameters to request on the Proxmox SSH
// session. It forwards the client's parameters when available, or falls
// back to sane defaults (important: pct/even qm crash without a PTY).
func effectivePty(ptyReq *PtyRequest) (term string, h int, w int, modes gossh.TerminalModes) {
	p := ptyReq
	if p == nil {
		p = &PtyRequest{Term: termXterm256Color, Width: 80, Height: 24}
	}
	return p.Term, int(p.Height), int(p.Width), parseModes(p.Modes)
}

// guestConsoleCmd returns the correct Proxmox shell command for the guest type.
func guestConsoleCmd(guest *models.Guest) (string, error) {
	switch guest.Type {
	case models.GuestTypeCT:
		return fmt.Sprintf("pct enter %d", guest.ProxmoxID), nil
	case models.GuestTypeVM:
		return fmt.Sprintf("qm terminal %d", guest.ProxmoxID), nil
	default:
		return "", fmt.Errorf("unknown guest type %q", guest.Type)
	}
}

// printConnectionBanner writes the pre-connection info banner to the channel.
// It is called by every code path that is about to proxy to a guest so the
// user always sees the same message regardless of how they initiated the
// connection (interactive picker, direct identifier, CLI 'guest connect', etc.).
// We write directly to channel with explicit \r\n — the channel is in raw PTY
// mode, so bare \n alone would not advance the cursor to column 0.
func printConnectionBanner(channel gossh.Channel, guest *models.Guest, inst *models.ProxmoxInstance) {
	_, _ = fmt.Fprintf(channel, "Connecting to %s (%s %d) on %s...\r\n",
		guest.Name, guest.Type, guest.ProxmoxID, inst.Name)
	_, _ = fmt.Fprint(channel, "Press Ctrl+A X to terminate the connection.\r\n")
}

// writeErr writes msg to stderr, always with \r\n line endings.
func writeErr(channel gossh.Channel, _ *PtyRequest, msg string) {
	_, _ = fmt.Fprintf(newCRLFWriter(channel.Stderr()), "%s\r\n", msg)
}

