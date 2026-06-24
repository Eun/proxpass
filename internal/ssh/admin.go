package ssh

import (
	"io"
	"log"

	"proxpass/internal/db"

	tea "github.com/charmbracelet/bubbletea"
	gossh "golang.org/x/crypto/ssh"
)

// AdminSessionHandler is called for every authenticated admin session.
// It receives the raw SSH channel and request stream.
type AdminSessionHandler func(channel gossh.Channel, reqs <-chan *gossh.Request, repo db.Repository)

// DefaultAdminHandler returns an AdminSessionHandler that performs the SSH
// pty-req / shell handshake and then runs runTUI on the channel.
// runTUI should be tui.RunTUI (injected to avoid an import cycle).
//
//nolint:gocognit // SSH admin session handler requires deep branching for request types
func DefaultAdminHandler(
	_ func(repo db.Repository, input io.Reader, output io.Writer) error,
	logger *log.Logger,
) AdminSessionHandler {
	return func(channel gossh.Channel, reqs <-chan *gossh.Request, repo db.Repository) {
		defer func() { _ = channel.Close() }()

		// Drain requests until we get "shell" or "exec". Along the way,
		// acknowledge "pty-req" and collect the initial terminal size.
		var initialWidth, initialHeight int
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
				initialWidth = int(p.Width)
				initialHeight = int(p.Height)
				if req.WantReply {
					_ = req.Reply(true, nil)
				}

			case "shell", "exec":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				// Remaining requests on this channel (e.g. window-change)
				// will be forwarded to the Bubble Tea program below.
				remaining = reqs
				goto startTUI

			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
		// If the channel closed without a shell request, nothing to do.
		return

	startTUI:
		_ = initialWidth  // available for future use
		_ = initialHeight // available for future use

		// Build the Bubble Tea program over the SSH channel.
		opts := []tea.ProgramOption{
			tea.WithInput(channel),
			tea.WithOutput(channel),
			tea.WithAltScreen(),
		}
		m := tuiModelFactory(repo)
		p := tea.NewProgram(m, opts...)

		// Forward window-change requests as tea.WindowSizeMsg.
		if remaining != nil {
			go func() {
				for req := range remaining {
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
		}

		if _, err := p.Run(); err != nil {
			logger.Printf("admin tui error: %v", err)
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
