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

	"proxpass/internal/cli"
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

// Terminal type constants.
const (
	termXterm         = "xterm"
	termXterm256Color = "xterm-256color"
)

type GuestNotFoundError struct {
	GuestName string
}

func (e *GuestNotFoundError) Error() string {
	return fmt.Sprintf("guest %q not found", e.GuestName)
}

func (e *GuestNotFoundError) Is(err error) bool {
	_, ok := err.(*GuestNotFoundError)
	return ok
}

// isHelpCommand returns true if the exec command should be routed to the help output.
// This covers 'help', '--help', '-h', and empty (for help on shell login).
func isHelpCommand(cmd string) bool {
	for _, v := range []string{"help", "--help", "-h"} {
		if strings.EqualFold(cmd, v) {
			return true
		}
	}
	return false
}

// interactiveGuestPicker shows the TUI guest picker and proxies to the
// selected guest. It is shared by both the admin and client paths.
//
// If clientID == 0, all guests are shown (admin path).
// If clientID > 0, only guests this client has access to are shown.
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
	label := "admin"
	if clientID != 0 {
		label = fmt.Sprintf("client/%d", clientID)
	}

	guests, err := repo.ListGuests(ctx)
	if err != nil {
		logger.Printf("%s: failed to list guests for picker: %v", label, err)
		writeErr(channel, ptyReq, "internal error")
		go gossh.DiscardRequests(remaining)
		return
	}

	// When a client ID is provided, filter guests to only those the client has access to.
	if clientID != 0 {
		for i := len(guests) - 1; i >= 0; i-- {
			ok, accessErr := repo.HasAccess(ctx, clientID, guests[i].ID)
			if accessErr != nil {
				writeErr(channel, ptyReq, fmt.Sprintf("Error: %v", accessErr))
				go gossh.DiscardRequests(remaining)
				return
			}
			if !ok {
				guests = append(guests[:i], guests[i+1:]...)
			}
		}
	}

	if len(guests) == 0 {
		_, _ = fmt.Fprintf(newCRLFWriter(channel.Stderr()), "\r\nNo guests discovered.\r\n")
		go gossh.DiscardRequests(remaining)
		return
	}

	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		logger.Printf("%s: failed to list instances for picker: %v", label, err)
		writeErr(channel, ptyReq, "internal error")
		go gossh.DiscardRequests(remaining)
		return
	}

	instMap := make(map[int64]string, len(instances))
	instByID := make(map[int64]*models.ProxmoxInstance, len(instances))
	for _, inst := range instances {
		instMap[inst.ID] = inst.Name
		instByID[inst.ID] = inst
	}

	// Drain remaining SSH requests while the picker runs.
	go gossh.DiscardRequests(remaining)

	guest, _, pickErr := tui.PickGuest(channel, channel, guests, instMap, ptyReq.Width, ptyReq.Height)
	if pickErr != nil {
		logger.Printf("%s: picker error: %v", label, pickErr)
		return
	}
	if guest == nil {
		// User cancelled.
		return
	}

	inst := instByID[guest.InstanceID]
	if inst == nil {
		writeErr(channel, ptyReq, fmt.Sprintf("instance for guest %q not found", guest.Name))
		return
	}

	_, _ = fmt.Fprintf(newCRLFWriter(channel), "Connecting to %s (%s %d)...\r\n",
		guest.Name, guest.Type, guest.ProxmoxID)

	proxyReqs := make(chan *gossh.Request, 4)
	defer close(proxyReqs)
	if proxyErr := proxier.ProxyToGuest(channel, proxyReqs, guest, inst, ptyReq, logger); proxyErr != nil {
		logger.Printf("%s: proxy error: %v", label, proxyErr)
	}
}

// proxyToGuest connects to the Proxmox host via SSH, starts the appropriate
// console command, and copies data bidirectionally between the client channel
// and the remote session.
//
//nolint:gocognit // SSH proxy requires sequential setup of pipes, goroutines, and teardown
func proxyToGuest(
	clientChan gossh.Channel,
	clientReqs <-chan *gossh.Request,
	guest *models.Guest,
	inst *models.ProxmoxInstance,
	ptyReq *PtyRequest,
	_ *log.Logger,
) error {
	// Load the private key for the Proxmox host.
	// SSHKey (inline PEM stored in DB) takes precedence over SSHKeyPath (file path).
	var keyBytes []byte
	if inst.SSHKey != "" {
		keyBytes = []byte(inst.SSHKey)
	} else {
		var err error
		keyBytes, err = os.ReadFile(inst.SSHKeyPath)
		if err != nil {
			return fmt.Errorf("reading proxmox key %s: %w", inst.SSHKeyPath, err)
		}
	}
	signer, err := gossh.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("parsing proxmox key: %w", err)
	}

	addr := net.JoinHostPort(inst.SSHHost, strconv.Itoa(inst.SSHPort))
	config := &gossh.ClientConfig{
		User:            inst.SSHUser,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // Proxmox host verification is out of scope.
	}

	client, err := gossh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("dialing proxmox %s: %w", addr, err)
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("opening remote session: %w", err)
	}
	defer func() { _ = session.Close() }()

	// Both pct enter (CT) and qm terminal (VM) use socat internally and
	// require a PTY on the Proxmox SSH unconditionally. Without one,
	// socat's tcgetattr(0, ...) call fails with ENOTTY, causing the console
	// to hang or immediately exit.
	//
	// Use the client's PTY parameters when available; fall back to a sane
	// default (xterm-256color 80¤24) for non-interactive callers (e.g. ssh -T).
	effectivePty := ptyReq
	if effectivePty == nil {
		effectivePty = &PtyRequest{Term: termXterm256Color, Width: 80, Height: 24}
	}
	if err := session.RequestPty(
		effectivePty.Term,
		int(effectivePty.Height),
		int(effectivePty.Width),
		parseModes(effectivePty.Modes),
	); err != nil {
		return fmt.Errorf("requesting remote pty: %w", err)
	}

	// Build the command for the guest type.
	var cmd string
	switch guest.Type {
	case models.GuestTypeCT:
		cmd = fmt.Sprintf("pct enter %d", guest.ProxmoxID)
	case models.GuestTypeVM:
		cmd = fmt.Sprintf("qm terminal %d", guest.ProxmoxID)
	default:
		return fmt.Errorf("unknown guest type %q", guest.Type)
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
				switch req.Type {
				case reqTypeWinChange:
					w, h, parseErr := parseWindowChange(req.Payload)
					if parseErr == nil {
						_ = session.WindowChange(int(h), int(w))
					}
					if req.WantReply {
						_ = req.Reply((parseErr == nil), nil)
					}
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}
	}()

	// client → remote stdin.
	go func() {
		_, _ = io.Copy(remoteStdin, clientChan)
		_ = remoteStdin.Close()
	}()

	// remote stdout → client
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientChan, remoteStdout)
	}()

	// remote stderr → client stderr
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientChan.Stderr(), remoteStderr)
	}()

	err = session.Wait()
	close(done)
	_ = remoteStdin.Close()
	_ = session.Close()
	_ = client.Close()
	wg.Wait()
	return err
}

// writeErr writes a message to the channel's stderr, using \r\n line endings
// when a PTY is active.
func writeErr(channel gossh.Channel, ptyReq *PtyRequest, msg string) {
	var w io.Writer
	if ptyReq != nil {
		w = newCRLFWriter(channel.Stderr())
	} else {
		w = channel.Stderr()
	}
	_, _ = fmt.Fprintf(w, "%s\r\n", msg)
}

// writeGuestList fetches all guests from repo and prints a formatted table to w.
// Errors are logged but do not interrupt the caller.
func writeGuestList(ctx context.Context, w io.Writer, repo db.Repository, logger *log.Logger, label string) {
	guests, err := repo.ListGuests(ctx)
	if err != nil {
		logger.Printf("%s: failed to list guests for shell listing: %v", label, err)
		return
	}
	if len(guests) == 0 {
		_, _ = fmt.Fprintf(w, "\r\nNo guests discovered.\r\n")
		return
	}
	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		logger.Printf("%s: failed to list instances for shell listing: %v", label, err)
		return
	}
	instMap := make(map[int64]string, len(instances))
	for _, inst := range instances {
		instMap[inst.ID] = inst.Name
	}
	_, _ = fmt.Fprintf(w, "\r\nAvailable guests:\r\n")
	_, _ = fmt.Fprintf(w, "%-6s %-6s %-24s %-10s %s\r\n", "TYPE", "VMID", "NAME", "STATUS", "INSTANCE")
	for _, g := range guests {
		instName := instMap[g.InstanceID]
		if instName == "" {
			instName = fmt.Sprintf("(id:%d)", g.InstanceID)
		}
		_, _ = fmt.Fprintf(w, "%-6s %-6d %-24s %-10s %s\r\n",
			g.Type, g.ProxmoxID, g.Name, g.Status, instName)
	}
}

// handleClientSession is invoked for every authenticated client channel.
// The guest target is passed as the SSH exec command:
//
//	ssh -t -p 2222 host ct100
//	ssh -t -p 2222 host rome:ct101
//
// Omitting the command (a plain shell with PTY) shows the interactive picker.
// Passing no PTY at all (ssh without -t) fails early with a clear error.
// Passing 'help' or '--help' as the command writes usage information.
//
//nolint:gocognit,funlen // SSH session handling requires sequential branching
func handleClientSession(
	channel gossh.Channel,
	reqs <-chan *gossh.Request,
	conn *gossh.ServerConn,
	repo db.Repository,
	proxier GuestProxier,
	logger *log.Logger,
) {
	defer func() { _ = channel.Close() }()

	ctx := context.Background()
	clientName := conn.Permissions.Extensions["client_name"]

	// Wait for the exec request that carries the guest identifier.
	var execCmd string
	var ptyReq *PtyRequest
	var remaining <-chan *gossh.Request
	for req := range reqs {
		switch req.Type {
		case reqTypePTY:
			p, err := parsePtyReq(req.Payload)
			if err != nil {
				logger.Printf("client %s: bad pty-req: %v", clientName, err)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			ptyReq = p
			if req.WantReply {
				_ = req.Reply(true, nil)
			}

		case reqTypeExec:
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			if len(req.Payload) >= 4 {
				cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
				if len(req.Payload) >= 4+cmdLen {
					execCmd = string(req.Payload[4 : 4+cmdLen])
				}
			}
			remaining = reqs
			goto handleGuest

		case reqTypeShell:
			// Plain shell without an identifier.
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			remaining = reqs
			goto handleGuest

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
	return

handleGuest:
	// A PTY is required for all interactive guest access. Fail early with
	// a clear error so the user knows to add 'ssh -t' or 'RequestTTY no'.
	if failIfNoPtyRequest(channel.Stderr(), ptyReq) {
		logger.Printf("client %s: no pty-req received; refusing connection", clientName)
		go gossh.DiscardRequests(remaining)
		return
	}

	// Route 'help', '--help', '-h' to a usage message.
	if isHelpCommand(execCmd) {
		w := newCRLFWriter(channel.Stderr())
		_, _ = fmt.Fprintf(w,
			"Usage: ssh -t <host> [<instance>:]<identifier>\r\n\r\n"+
				"Identifier can be a VMID (e.g. 100), type+VMID (e.g. ct100), or name (e.g. webserver).\r\n"+
				"If multiple guests match, prefix with the instance name (e.g. rome:ct101).\r\n")
		writeGuestList(ctx, w, repo, logger, clientName)
		go gossh.DiscardRequests(remaining)
		return
	}

	// Resolve client and check access.
	client, err := repo.GetClientByName(ctx, clientName)
	if err != nil {
		logger.Printf("client %s: lookup failed: %v", clientName, err)
		writeErr(channel, ptyReq, "internal error")
		go gossh.DiscardRequests(remaining)
		return
	}

	// No exec command (plain shell): show the interactive TUI picker.
	if execCmd == "" {
		interactiveGuestPicker(ctx, client.ID, channel, remaining, repo, proxier, ptyReq, logger)
		return
	}

	// Parse the exec command as the guest identifier.
	instName, identifier := cli.ParseGuestTarget(execCmd)

	guests, err := repo.ListGuests(ctx)
	if err != nil {
		logger.Printf("client %s: failed to list guests: %v", clientName, err)
		writeErr(channel, ptyReq, "internal error")
		go gossh.DiscardRequests(remaining)
		return
	}

	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		logger.Printf("client %s: failed to list instances: %v", clientName, err)
		writeErr(channel, ptyReq, "internal error")
		go gossh.DiscardRequests(remaining)
		return
	}

	guest, inst, err := cli.ResolveGuestAndInstance(identifier, instName, guests, instances)
	if err != nil {
		logger.Printf("client %s: %v", clientName, err)
		writeErr(channel, ptyReq, err.Error())
		go gossh.DiscardRequests(remaining)
		return
	}

	ok, err := repo.HasAccess(ctx, client.ID, guest.ID)
	if err != nil {
		logger.Printf("client %s: access check failed: %v", clientName, err)
		writeErr(channel, ptyReq, "internal error")
		go gossh.DiscardRequests(remaining)
		return
	}
	if !ok {
		logger.Printf("client %s: access denied to guest %s", clientName, guest.Name)
		writeErr(channel, ptyReq, "access denied")
		go gossh.DiscardRequests(remaining)
		return
	}

	if err := proxier.ProxyToGuest(channel, remaining, guest, inst, ptyReq, logger); err != nil {
		logger.Printf("client %s: proxy error: %v", clientName, err)
		writeErr(channel, ptyReq, fmt.Sprintf("proxy error: %v", err))
	}
}
