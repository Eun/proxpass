package ssh

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"

	"proxpass/internal/cli"
	"proxpass/internal/db"
	"proxpass/internal/proxmox"

	gossh "golang.org/x/crypto/ssh"
)

// AdminSessionHandler is called for every authenticated admin session.
// conn is the underlying server connection. The SSH username is ignored;
// the guest target is passed as the SSH first argument:
//
//	ssh <host> [instance:]<identifier>    # proxy directly to guest
//	ssh <host> <cli command>              # run admin CLI
//	ssh <host>                             # show CLI help
type AdminSessionHandler func(channel gossh.Channel, reqs <-chan *gossh.Request, conn *gossh.ServerConn, repo db.Repository)

// DefaultAdminHandler returns an AdminSessionHandler that:
//   - Plain shell: shows the admin CLI help.
//   - Exec command that looks like a guest identifier (e.g. "ct100", "rome:ct101"):
//     proxies directly to that guest.
//   - Exec command that is not a guest identifier (e.g. "guest ls"):
//     runs the admin CLI with that command.
//
// The SSH username is ignored entirely.
func DefaultAdminHandler( //nolint:gocognit // SSH session handler
	proxier GuestProxier,
	discoverer proxmox.DiscovererFactory,
	logger *log.Logger,
) AdminSessionHandler {
	return func(channel gossh.Channel, reqs <-chan *gossh.Request, _ *gossh.ServerConn, repo db.Repository) {
		defer func() { _ = channel.Close() }()

		// Wait for shell or exec request.
		var execCmd string
		var ptyReq *PtyRequest
		var remaining <-chan *gossh.Request

		for req := range reqs {
			switch req.Type {
			case reqTypePTY:
				p, err := parsePtyReq(req.Payload)
				if err != nil {
					logger.Printf("admin: bad pty-req: %v", err)
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
				// Parse command from exec payload: uint32 len + string
				if len(req.Payload) >= 4 {
					cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
					if len(req.Payload) >= 4+cmdLen {
						execCmd = string(req.Payload[4 : 4+cmdLen])
					}
				}
				remaining = reqs
				goto handleCommand

			case reqTypeShell:
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				// Interactive shell -- show help
				remaining = reqs
				goto handleCommand

			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
		return

	handleCommand:
		// If the exec command looks like a guest identifier, proxy directly.
		// An identifier is a single token (no internal spaces).
		// A CLI command (like "guest ls") has a space and always runs the CLI.
		proxied, proxyErr := tryAdminProxy(context.Background(), execCmd, channel, remaining, repo, proxier, ptyReq, logger)
		if proxied {
			return
		}
		if proxyErr != nil {
			// Looked like a guest identifier but could not be resolved.
			// Write a clear error and exit -- do not fall through to the CLI.
			writeErr(channel, ptyReq, fmt.Sprintf("Error: %v", proxyErr))
			go gossh.DiscardRequests(remaining)
			return
		}

		// Discard remaining requests in background
		go func() {
			for req := range remaining {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}()

		// When a PTY is active the SSH channel is in raw mode:
		// the client's terminal expects \r\n line endings, not bare \n.
		var out, errOut io.Writer
		if ptyReq != nil {
			out = newCRLFWriter(channel)
			errOut = newCRLFWriter(channel.Stderr())
		} else {
			out = channel
			errOut = channel.Stderr()
		}

		deps := &cli.Deps{
			Repo:       repo,
			Discoverer: discoverer,
			Out:        out,
			ErrOut:     errOut,
		}

		var argv []string
		if execCmd != "" {
			// Split the exec command into argv
			argv = append([]string{"proxpass"}, splitArgs(execCmd)...)
		} else {
			// Interactive shell with no command -- list available guests
			argv = []string{"proxpass", "guest", "ls"}
		}

		root := cli.Build(deps)
		if err := root.Run(context.Background(), argv); err != nil {
			_, _ = fmt.Fprintf(channel.Stderr(), "Error: %v\r\n", err)
		}

		// If guest connect was requested, proxy to the guest
		if deps.ConnectRequest != nil {
			_, _ = fmt.Fprintf(channel, "Connecting to %s (%s %d)...\r\n",
				deps.ConnectRequest.Guest.Name,
				deps.ConnectRequest.Guest.Type,
				deps.ConnectRequest.Guest.ProxmoxID)

			proxyReqs := make(chan *gossh.Request, 4)
			// remaining is already being drained above; for proxy we
			// don't need request forwarding since the CLI session is over
			defer close(proxyReqs)

			if err := proxier.ProxyToGuest(
				channel, proxyReqs,
				deps.ConnectRequest.Guest,
				deps.ConnectRequest.Instance,
				ptyReq, logger,
			); err != nil {
				logger.Printf("admin: proxy error: %v", err)
			}
		}
	}
}

// tryAdminProxy attempts to interpret the exec command as a guest identifier
// and, if successful, proxies the admin channel directly to that guest.
//
// A command is treated as a guest identifier when it is a single token
// (no spaces). A multi-word exec like "guest ls" always runs the CLI.
//
// Return values:
//   - (true, nil)   -- proxy was started; caller must return.
//   - (false, nil)  -- command is not a single-token identifier; fall through.
//   - (false, err)  -- looked like an identifier but resolution failed;
//     caller should report the error and return.
//
// Admins bypass HasAccess checks and can reach any guest unconditionally.
func tryAdminProxy(
	ctx context.Context,
	execCmd string,
	channel gossh.Channel,
	remaining <-chan *gossh.Request,
	repo db.Repository,
	proxier GuestProxier,
	ptyReq *PtyRequest,
	logger *log.Logger,
) (bool, error) {
	// Only single-token commands are treated as guest identifiers.
	// An empty execCmd means a plain shell; a multi-word command means CLI.
	if execCmd == "" || strings.ContainsRune(execCmd, ' ') {
		return false, nil
	}

	// Parse optional instance:identifier format.
	instName, identifier := parseGuestTarget(execCmd)

	guests, err := repo.ListGuests(ctx)
	if err != nil {
		return false, fmt.Errorf("listing guests: %w", err)
	}

	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		return false, fmt.Errorf("listing instances: %w", err)
	}

	guest, inst, err := resolveGuestAndInstance(identifier, instName, guests, instances)
	if err != nil {
		return false, err
	}

	// Forward remaining SSH requests to the proxy via a buffered bridge channel.
	proxyReqs := make(chan *gossh.Request, 4)
	go func() {
		for req := range remaining {
			select {
			case proxyReqs <- req:
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
		close(proxyReqs)
	}()

	if proxyErr := proxier.ProxyToGuest(channel, proxyReqs, guest, inst, ptyReq, logger); proxyErr != nil {
		logger.Printf("admin: proxy to guest %q error: %v", guest.Name, proxyErr)
	}
	return true, nil
}

// splitArgs does a simple shell-like split of a command string.
// It handles double-quoted strings but not single quotes or escapes.
func splitArgs(s string) []string {
	var args []string
	var current strings.Builder
	inQuote := false

	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}
