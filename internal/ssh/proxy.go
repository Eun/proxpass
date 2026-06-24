package ssh

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"proxpass/internal/db"
	"proxpass/internal/models"

	gossh "golang.org/x/crypto/ssh"
)

// handleClientSession is invoked for every authenticated client channel.
// The SSH username on the connection is interpreted as the target guest name.
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
	guestName := conn.User()
	clientName := conn.Permissions.Extensions["client_name"]

	// Resolve guest by name.
	guests, err := repo.ListGuests(ctx)
	if err != nil {
		logger.Printf("client %s: failed to list guests: %v", clientName, err)
		_, _ = fmt.Fprintf(channel.Stderr(), "internal error\r\n")
		return
	}

	var guest *models.Guest
	for _, g := range guests {
		if g.Name == guestName {
			guest = g
			break
		}
	}
	if guest == nil {
		logger.Printf("client %s: guest %q not found", clientName, guestName)
		_, _ = fmt.Fprintf(channel.Stderr(), "guest %q not found\r\n", guestName)
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
		logger.Printf("client %s: access denied to guest %s", clientName, guestName)
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
			clientName, guest.InstanceID, guestName)
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

	var wg sync.WaitGroup

	// Forward window-change requests from the client to the remote session.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range clientReqs {
			switch req.Type {
			case "window-change":
				w, h, err := parseWindowChange(req.Payload)
				if err == nil {
					_ = session.WindowChange(int(h), int(w))
				}
				if req.WantReply {
					_ = req.Reply(err == nil, nil)
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}()

	// client → remote stdin
	wg.Add(1)
	go func() {
		defer wg.Done()
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
	// Close the remote session and SSH client to unblock the
	// io.Copy goroutines. We do NOT close clientChan here so
	// that the admin handler can reuse the channel for the TUI
	// after the proxy session ends.
	_ = session.Close()
	_ = client.Close()
	wg.Wait()
	return err
}
