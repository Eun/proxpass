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

	gossh "golang.org/x/crypto/ssh"
)

// handleClientSession is invoked for every authenticated client channel.
// The SSH username on the connection is used to resolve the target guest.
// Resolution order: numeric VMID → type+VMID (e.g. ct100) → name.
//
//nolint:gocognit // SSH session handling requires sequential branching
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
	identifier := conn.User()
	clientName := conn.Permissions.Extensions["client_name"]

	guests, err := repo.ListGuests(ctx)
	if err != nil {
		logger.Printf("client %s: failed to list guests: %v", clientName, err)
		_, _ = fmt.Fprintf(channel.Stderr(), "internal error\r\n")
		return
	}

	guest, err := resolveGuest(identifier, guests)
	if err != nil {
		logger.Printf("client %s: %v", clientName, err)
		_, _ = fmt.Fprintf(channel.Stderr(), "%v\r\n", err)
		return
	}

	// Resolve client and check access.
	client, err := repo.GetClientByName(ctx, clientName)
	if err != nil {
		logger.Printf("client %s: lookup failed: %v", clientName, err)
		_, _ = fmt.Fprintf(channel.Stderr(), "internal error\r\n")
		return
	}

	ok, err := repo.HasAccess(ctx, client.ID, guest.ID)
	if err != nil {
		logger.Printf("client %s: access check failed: %v", clientName, err)
		_, _ = fmt.Fprintf(channel.Stderr(), "internal error\r\n")
		return
	}
	if !ok {
		logger.Printf("client %s: access denied to guest %s", clientName, guest.Name)
		_, _ = fmt.Fprintf(channel.Stderr(), "access denied\r\n")
		return
	}

	// Find the Proxmox instance that owns this guest.
	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		logger.Printf("client %s: failed to list instances: %v", clientName, err)
		_, _ = fmt.Fprintf(channel.Stderr(), "internal error\r\n")
		return
	}

	var inst *models.ProxmoxInstance
	for _, i := range instances {
		if i.ID == guest.InstanceID {
			inst = i
			break
		}
	}
	if inst == nil {
		logger.Printf("client %s: proxmox instance %d not found for guest %s",
			clientName, guest.InstanceID, guest.Name)
		_, _ = fmt.Fprintf(channel.Stderr(), "internal error\r\n")
		return
	}

	// Collect the initial PTY request (if any) before proxying.
	var pty *PtyRequest
	// We drain requests in the background once the proxy starts, but we need
	// to handle the initial pty-req and shell/exec first.
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			p, err := parsePtyReq(req.Payload)
			if err != nil {
				logger.Printf("client %s: bad pty-req: %v", clientName, err)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			pty = p
			if req.WantReply {
				_ = req.Reply(true, nil)
			}

		case "shell", "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			// Now proxy the session. Window-change requests that arrive
			// later are forwarded inside proxyToGuest.
			if err := proxier.ProxyToGuest(channel, reqs, guest, inst, pty, logger); err != nil {
				logger.Printf("client %s: proxy error: %v", clientName, err)
				_, _ = fmt.Fprintf(channel.Stderr(), "proxy error: %v\r\n", err)
			}
			return

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
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
	keyBytes, err := os.ReadFile(inst.SSHKeyPath)
	if err != nil {
		return fmt.Errorf("reading proxmox key %s: %w", inst.SSHKeyPath, err)
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

	// Request a PTY on the remote side if the client asked for one.
	if ptyReq != nil {
		modes := gossh.TerminalModes{}
		if err := session.RequestPty(ptyReq.Term, int(ptyReq.Height), int(ptyReq.Width), modes); err != nil {
			return fmt.Errorf("requesting remote pty: %w", err)
		}
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
	// Uses select on done so we don't block on clientReqs, which isn't closed
	// until after proxyToGuest returns (the bridge channel is closed in admin.go).
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
				case "window-change":
					w, h, parseErr := parseWindowChange(req.Payload)
					if parseErr == nil {
						_ = session.WindowChange(int(h), int(w))
					}
					if req.WantReply {
						_ = req.Reply(parseErr == nil, nil)
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
	// NOT in the WaitGroup: clientChan.Read blocks until the admin session
	// closes the channel, which happens after proxyToGuest returns.
	// When we close remoteStdin below the goroutine's next Write will fail
	// and it will exit.
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
	// Signal the request-forwarding goroutine and tear down the remote
	// side.  We do NOT close clientChan so the admin handler can reuse
	// the channel for the TUI after the proxy session ends.
	close(done)
	_ = remoteStdin.Close()
	_ = session.Close()
	_ = client.Close()
	wg.Wait()
	return err
}

// resolveGuest looks up a guest by the identifier the SSH client
// provided as the username. Resolution order:
//
//  1. Numeric VMID — e.g. "100" matches ProxmoxID 100.
//     If multiple guests share the same VMID (across instances),
//     an error is returned asking the user to use type+id.
//  2. Type+VMID — e.g. "ct100" or "vm200" (case-insensitive).
//     Always unique within a type.
//  3. Guest name — e.g. "webserver" (case-insensitive).
//     If multiple guests share the same name, an error is returned.
//
//nolint:gocognit // sequential resolution tiers require nested checks
func resolveGuest(
	identifier string,
	guests []*models.Guest,
) (*models.Guest, error) {
	lower := strings.ToLower(identifier)

	// --- 1. Try numeric VMID ---
	if vmid, err := strconv.Atoi(identifier); err == nil {
		var matches []*models.Guest
		for _, g := range guests {
			if g.ProxmoxID == vmid {
				matches = append(matches, g)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		if len(matches) > 1 {
			return nil, fmt.Errorf(
				"VMID %d matches %d guests; use type+id instead "+
					"(e.g. %s%d)",
				vmid, len(matches),
				matches[0].Type, vmid)
		}
		// No match by VMID — fall through to other methods.
	}

	// --- 2. Try type+VMID (e.g. "ct100", "vm200") ---
	for _, prefix := range []models.GuestType{
		models.GuestTypeCT, models.GuestTypeVM,
	} {
		p := string(prefix)
		if strings.HasPrefix(lower, p) {
			if vmid, err := strconv.Atoi(
				lower[len(p):],
			); err == nil {
				for _, g := range guests {
					if g.Type == prefix &&
						g.ProxmoxID == vmid {
						return g, nil
					}
				}
			}
		}
	}

	// --- 3. Try guest name (case-insensitive) ---
	var matches []*models.Guest
	for _, g := range guests {
		if strings.EqualFold(g.Name, identifier) {
			matches = append(matches, g)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		var hints []string
		for _, g := range matches {
			hints = append(hints,
				fmt.Sprintf("%s%d", g.Type, g.ProxmoxID))
		}
		return nil, fmt.Errorf(
			"name %q matches %d guests; use a unique id: %s",
			identifier, len(matches),
			strings.Join(hints, ", "))
	}

	return nil, fmt.Errorf("guest %q not found", identifier)
}
