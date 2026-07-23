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
// conn is the underlying server connection; its User() method returns
// the SSH username the client supplied, which is used to determine
// whether to proxy directly to a guest or run the admin CLI.
type AdminSessionHandler func(channel gossh.Channel, reqs <-chan *gossh.Request, conn *gossh.ServerConn, repo db.Repository)

// DefaultAdminHandler returns an AdminSessionHandler that runs
// CLI commands received via SSH exec requests.
func DefaultAdminHandler( //nolint:gocognit // SSH session handler
	proxier GuestProxier,
	discoverer proxmox.DiscovererFactory,
	logger *log.Logger,
) AdminSessionHandler {
	return func(channel gossh.Channel, reqs <-chan *gossh.Request, conn *gossh.ServerConn, repo db.Repository) {
		defer func() { _ = channel.Close() }()

		// Wait for shell or exec request.
		var execCmd string
		var ptyReq *PtyRequest
		var remaining <-chan *gossh.Request

		// Capture the SSH username so we can detect a direct guest-proxy request.
		identifier := conn.User()

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
				// Interactive shell — show help
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
		// If an exec command was provided (e.g. "ssh dsm@host guest ls"), always
		// run the CLI regardless of the SSH username. The username is used only
		// for direct shell sessions (no exec payload).
		//
		// If the SSH username looks like a guest identifier (e.g. "ct100",
		// "vm200", "webserver") and no exec command was given, proxy the admin
		// directly to that guest. Admins bypass HasAccess checks — they can
		// reach any guest.
		proxied, proxyErr := tryAdminProxy(context.Background(), identifier, execCmd, channel, remaining, repo, proxier, ptyReq, logger)
		if proxied {
			return
		}
		if proxyErr != nil {
			// The identifier looked like a guest but could not be resolved or
			// proxied. Write a clear error and exit — do not fall through to
			// the admin CLI, which would confusingly show --help.
			var w io.Writer
			if ptyReq != nil {
				w = newCRLFWriter(channel.Stderr())
			} else {
				w = channel.Stderr()
			}
			_, _ = fmt.Fprintf(w, "Error: %v\r\n", proxyErr)
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
			// Interactive shell — show usage
			argv = []string{"proxpass", "--help"}
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

// cliOnlyUsernames is the set of SSH usernames that always open the admin CLI
// regardless of what guests exist in the database. These are conventional
// admin usernames; their presence as the SSH username unambiguously signals
// "I want the CLI, not a guest proxy".
var cliOnlyUsernames = map[string]bool{
	"":       true,
	"root":   true,
	"admin":  true,
	"manage": true,
}

// tryAdminProxy attempts to resolve the SSH username as a guest identifier and,
// if successful, proxies the admin channel directly to that guest.
//
// Return values:
//   - (true, nil)  — proxy was started; caller must return.
//   - (false, nil) — username is a CLI-only name, or an exec command was
//     supplied; fall through to the CLI.
//   - (false, err) — username looks like a guest but could not be resolved or
//     proxied; caller should report the error and return.
//
// Admins bypass HasAccess checks and can reach any guest unconditionally.
func tryAdminProxy(
	ctx context.Context,
	identifier string,
	execCmd string,
	channel gossh.Channel,
	remaining <-chan *gossh.Request,
	repo db.Repository,
	proxier GuestProxier,
	ptyReq *PtyRequest,
	logger *log.Logger,
) (bool, error) {
	// A CLI-only username always goes straight to the admin CLI.
	if cliOnlyUsernames[identifier] {
		return false, nil
	}
	// An exec payload (e.g. "guest ls") always runs the CLI, even when the
	// SSH username looks like a guest identifier.
	if execCmd != "" {
		return false, nil
	}

	guests, err := repo.ListGuests(ctx)
	if err != nil {
		return false, fmt.Errorf("listing guests: %w", err)
	}

	g, err := resolveGuest(identifier, guests)
	if err != nil {
		return false, err
	}

	inst := findInstanceByID(ctx, repo, g.InstanceID, logger)
	if inst == nil {
		return false, fmt.Errorf("proxmox instance for guest %q not found", g.Name)
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

	if proxyErr := proxier.ProxyToGuest(channel, proxyReqs, g, inst, ptyReq, logger); proxyErr != nil {
		logger.Printf("admin: proxy to guest %q error: %v", g.Name, proxyErr)
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
