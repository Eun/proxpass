package ssh

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"

	"proxpass/internal/db"
	"proxpass/internal/models"

	tea "github.com/charmbracelet/bubbletea"
	gossh "golang.org/x/crypto/ssh"
)

// AdminSessionHandler is called for every authenticated admin session.
// It receives the raw SSH channel and request stream.
type AdminSessionHandler func(channel gossh.Channel, reqs <-chan *gossh.Request, repo db.Repository)

// GuestSelector is implemented by the TUI model to indicate whether
// the admin selected a guest for connection. Defined here to avoid
// importing the tui package (which would create an import cycle).
type GuestSelector interface {
	GetSelectedGuest() *models.Guest
}

// reqBridge reads from the original SSH request channel and forwards each
// request to whichever consumer is currently active. Consumers are swapped
// atomically via set(). When no consumer is set, requests that require a
// reply are rejected.
type reqBridge struct {
	mu      sync.Mutex
	current chan *gossh.Request
}

func (b *reqBridge) set(ch chan *gossh.Request) {
	b.mu.Lock()
	b.current = ch
	b.mu.Unlock()
}

func (b *reqBridge) run(source <-chan *gossh.Request) {
	for req := range source {
		b.mu.Lock()
		ch := b.current
		b.mu.Unlock()
		if ch != nil {
			ch <- req
		} else if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

// DefaultAdminHandler returns an AdminSessionHandler that performs the SSH
// pty-req / shell handshake, runs the TUI, and optionally proxies the admin
// to a selected guest. When the proxy session ends the TUI is restarted,
// forming a TUI → proxy → TUI loop until the admin quits normally.
//
//nolint:gocognit // SSH admin session handler requires deep branching for request types
func DefaultAdminHandler(
	_ func(repo db.Repository, input io.Reader, output io.Writer) error,
	logger *log.Logger,
) AdminSessionHandler {
	return func(channel gossh.Channel, reqs <-chan *gossh.Request, repo db.Repository) {
		defer func() { _ = channel.Close() }()

		// --- Handshake: collect pty-req, wait for shell/exec ---
		var ptyReq *ptyRequest
		var remaining <-chan *gossh.Request

		for req := range reqs {
			switch req.Type {
			case "pty-req":
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

			case "shell", "exec":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				// Remaining requests on this channel (e.g. window-change)
				// will be dispatched through the reqBridge below.
				remaining = reqs
				goto sessionLoop

			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
		// Channel closed without a shell request — nothing to do.
		return

	sessionLoop:
		// Start the persistent request bridge that fans out SSH
		// requests to whichever consumer (TUI or proxy) is active.
		bridge := &reqBridge{}
		go bridge.run(remaining)

		for {
			// ---- Run the TUI ----
			tuiReqs := make(chan *gossh.Request, 4)
			bridge.set(tuiReqs)

			m := tuiModelFactory(repo)
			p := tea.NewProgram(m,
				tea.WithInput(channel),
				tea.WithOutput(channel),
				tea.WithAltScreen(),
			)

			// Forward window-change requests to BubbleTea while the TUI
			// is running.
			go func() {
				for req := range tuiReqs {
					switch req.Type {
					case "window-change":
						w, h, err := parseWindowChange(req.Payload)
						if err == nil {
							p.Send(tea.WindowSizeMsg{
								Width:  int(w),
								Height: int(h),
							})
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

			finalModel, err := p.Run()
			// Stop the bridge from writing to the (about to be closed)
			// tuiReqs channel, then close it to terminate the forwarder.
			bridge.set(nil)
			close(tuiReqs)

			if err != nil {
				logger.Printf("admin tui error: %v", err)
				return
			}

			// Did the admin select a guest to connect to?
			sel, ok := finalModel.(GuestSelector)
			if !ok || sel.GetSelectedGuest() == nil {
				return // normal quit
			}

			guest := sel.GetSelectedGuest()

			// Resolve the Proxmox instance that owns this guest.
			ctx := context.Background()
			instances, err := repo.ListProxmoxInstances(ctx)
			if err != nil {
				logger.Printf("admin: failed to list instances: %v", err)
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
				logger.Printf("admin: instance %d not found for guest %s", guest.InstanceID, guest.Name)
				_, _ = fmt.Fprintf(channel.Stderr(), "instance not found\r\n")
				return
			}

			// ---- Proxy to the guest ----
			_, _ = fmt.Fprintf(channel, "Connecting to %s (%s %d)...\r\n",
				guest.Name, guest.Type, guest.ProxmoxID)

			proxyReqs := make(chan *gossh.Request, 4)
			bridge.set(proxyReqs)

			proxyErr := proxyToGuest(channel, proxyReqs, guest, inst, ptyReq, logger)

			bridge.set(nil)
			close(proxyReqs)

			if proxyErr != nil {
				logger.Printf("admin: proxy error: %v", proxyErr)
			}

			// Loop back to restart the TUI.
		}
	}
}

// tuiModelFactory is a compile-time pluggable factory so that admin.go does
// not import the tui package (which would create a cycle via db).  It is set
// by the caller via SetTUIFactory.
var tuiModelFactory func(repo db.Repository) tea.Model

// SetTUIFactory installs the factory function used by DefaultAdminHandler to
// create a new TUI model. Call this once from main before starting the server.
func SetTUIFactory(f func(repo db.Repository) tea.Model) {
	tuiModelFactory = f
}
