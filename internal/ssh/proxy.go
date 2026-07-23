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

// handleClientSession is invoked for every authenticated client channel.
// The guest target is passed as the SSH exec command:
//
//	ssh -p 2222 host ct100
//	ssh -p 2222 host rome:ct101
//
// omitting the command (a plain shell) writes a help message and closes.
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
			// Plain shell without an identifier: tell the client how to use proxpass
			// and list the available guests.
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			var w io.Writer
			if ptyReq != nil {
				w = newCRLFWriter(channel.Stderr())
			} else {
				w = channel.Stderr()
			}
			_, _ = fmt.Fprintf(w,
				"Usage: ssh <host> [instance:]<identifier>\r\n\r\n"+
					"Identifier can be a VMID (e.g. 100), type+VMID (e.g. ct100), or name (e.g. webserver).\r\n"+
					"If multiple guests match, prefix with the instance name (e.g. rome:ct101).\r\n")
			writeGuestList(ctx, w, repo, logger, clientName)
			go gossh.DiscardRequests(reqs)
			return

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
	return

handleGuest:
	// Parse the exec command as the guest identifier.
	instName, identifier := parseGuestTarget(execCmd)

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

	guest, inst, err := resolveGuestAndInstance(identifier, instName, guests, instances)
	if err != nil {
		logger.Printf("client %s: %v", clientName, err)
		writeErr(channel, ptyReq, err.Error())
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
	// require a PTY on the Proxmox SSH session unconditionally. Without one,
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
	// the channel for the TIU after the proxy session ends.
	close(done)
	_ = remoteStdin.Close()
	_ = session.Close()
	_ = client.Close()
	wg.Wait()
	return err
}

// parseGuestTarget splits an optional "instance:identifier" string.
// If no colon is present, instanceName is empty.
func parseGuestTarget(s string) (instanceName, identifier string) {
	if idx := strings.IndexByte(s, ':'); idx >= 0 {
		return s[:idx], s[idx+1:]
	}
	return "", s
}

// resolveGuestAndInstance looks up a guest and its Proxmox instance by identifier
// and an optional instance name filter.
//
// Resolution order for identifier:
//  1. Numeric VMID.
//  2. Type+VMID (e.g. "ct100", "vm200").
//  3. Guest name (case-insensitive).
//
// If instName is non-empty, only guests on that instance are considered.
// If multiple guests match, an error is returned hinting to use instance:identifier.
func resolveGuestAndInstance(
	identifier string,
	instName string,
	guests []*models.Guest,
	instances []*models.ProxmoxInstance,
) (*models.Guest, *models.ProxmoxInstance, error) {
	// Build instance lookup map by ID and by name.
	instByID := make(map[int64]*models.ProxmoxInstance, len(instances))
	var instFilterID int64 = -1 // -1 means no filter
	switch {
	case instName != "":
		found := false
		for _, inst := range instances {
			instByID[inst.ID] = inst
			if strings.EqualFold(inst.Name, instName) {
				instFilterID = inst.ID
				found = true
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("instance %q not found", instName)
		}
	default:
		for _, inst := range instances {
			instByID[inst.ID] = inst
		}
	}

	// Filter guests by instance if a filter was given.
	var pool []*models.Guest
	if instFilterID >= 0 {
		for _, g := range guests {
			if g.InstanceID == instFilterID {
				pool = append(pool, g)
			}
		}
	} else {
		pool = guests
	}

	guest, err := resolveGuest(identifier, pool, instName == "" /* hintInstance*/)
	if err != nil {
		return nil, nil, err
	}

	inst := instByID[guest.InstanceID]
	if inst == nil {
		return nil, nil, fmt.Errorf("proxmox instance for guest %q not found", guest.Name)
	}
	return guest, inst, nil
}

// resolveGuest looks up a guest by the identifier within the given pool.
// Resolution order: numeric VMID → type+VMID (ct100, vm200) ‒ name.
//
// hintInstance controls whether error messages suggest using the
// instance:identifier format to disambiguate.
//
//nolint:gocognit,nestif // sequential resolution tiers require nested checks
func resolveGuest(
	identifier string,
	guests []*models.Guest,
	hintInstance bool,
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
			if hintInstance {
				return nil, fmt.Errorf(
					"VMID %d matches %d guests; use instance:identifier (see 'guest ls')",
					vmid, len(matches))
			}
			return nil, fmt.Errorf(
				"VMID %d matches %d guests; use type+id instead (e.g. %s%d)",
				vmid, len(matches), matches[0].Type, vmid)
		}
		// No match by VMID; fall through to other methods.
	}

	// --- 2. Try type+VMID (e.g. "ct100", "vm200") ---
	for _, prefix := range []models.GuestType{
		models.GuestTypeCT, models.GuestTypeVM,
	} {
		p := string(prefix)
		if strings.HasPrefix(lower, p) {
			if vmid, err := strconv.Atoi(lower[len(p):]); err == nil {
				for _, g := range guests {
					if g.Type == prefix && g.ProxmoxID == vmid {
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
		if hintInstance {
			return nil, fmt.Errorf(
				"name %q matches %d guests; use instance:identifier (see 'guest ls')",
				identifier, len(matches))
		}
		var hints []string
		for _, g := range matches {
			hints = append(hints, fmt.Sprintf("%s%d", g.Type, g.ProxmoxID))
		}
		return nil, fmt.Errorf(
			"name %q matches %d guests; use a unique id: %s",
			identifier, len(matches), strings.Join(hints, ", "))
	}

	return nil, fmt.Errorf("guest %q not found", identifier)
}

// writeGuestList fetches all guests from repo and prints a formatted table to w.
// Errors are logged but do not interrupt the caller.
func writeGuestList(ctx context.Context, w io.Writer, repo db.Repository, logger *log.Logger, clientName string) {
	guests, err := repo.ListGuests(ctx)
	if err != nil {
		logger.Printf("client %s: failed to list guests for shell listing: %v", clientName, err)
		return
	}
	if len(guests) == 0 {
		_, _ = fmt.Fprintf(w, "\r\nNo guests discovered.\r\n")
		return
	}
	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		logger.Printf("client %s: failed to list instances for shell listing: %v", clientName, err)
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
