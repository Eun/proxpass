// Package console attaches a local terminal to a Proxmox guest console.
//
// proxpass no longer implements an SSH server: OpenSSH's sshd owns the
// protocol and runs "proxpass session" as the login command. That means the
// terminal here is simply this process's stdin/stdout, already on a PTY
// allocated by sshd, and window resizes arrive as SIGWINCH rather than as SSH
// "window-change" requests.
package console

import (
	"fmt"
	"io"
	"log"
	"os"

	"proxpass/internal/models"
)

// Terminal describes the local terminal a session is attached to.
type Terminal struct {
	In   io.Reader
	Out  io.Writer
	Err  io.Writer
	Term string
	// Width and Height are the initial dimensions. Later changes are picked
	// up through Resizes.
	Width  int
	Height int
	// Resizes yields new dimensions as the terminal is resized. It may be nil
	// when the caller cannot observe resizes.
	Resizes <-chan Size

	// Raw reports whether Out/Err are a PTY that has been put into raw mode.
	//
	// Raw mode clears ONLCR, so the terminal stops translating "\n" into
	// "carriage return + line feed" and text printed with bare newlines
	// staircases down the screen. Anything writing proxpass's own UI must go
	// through UIOut/UIErr, which add that translation back.
	Raw bool
}

// UIOut returns the writer to use for proxpass's own output on this terminal.
//
// A guest console must keep writing to Out directly: its bytes are already
// correctly terminated and may be binary escape sequences in which a 0x0a is
// data rather than a line break.
func (t *Terminal) UIOut() io.Writer { return t.uiWriter(t.Out) }

// UIErr is UIOut for the error stream.
func (t *Terminal) UIErr() io.Writer { return t.uiWriter(t.Err) }

func (t *Terminal) uiWriter(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	if !t.Raw {
		return w
	}
	return NewCRLFWriter(w)
}

// Size is a terminal dimension update.
type Size struct {
	Width  int
	Height int
}

// Proxier attaches a terminal to a guest console.
type Proxier interface {
	Connect(term *Terminal, guest *models.Guest, inst *models.ProxmoxInstance, logger *log.Logger) error
}

// DefaultProxier dispatches to the termproxy WebSocket transport or the SSH
// transport depending on the instance's configured connection type.
type DefaultProxier struct {
	// PublicEndpoint is the hostname clients use to reach this proxpass. It
	// is shown in the status bar so a session says where it is as well as
	// what it is connected to, and is empty when the deployment has not been
	// told what its endpoint is.
	//
	// This is a field rather than a Connect parameter because it describes
	// the deployment, not the connection: it is the same for every guest and
	// never varies within a process.
	PublicEndpoint string
}

// Connect implements Proxier.
func (p DefaultProxier) Connect(
	term *Terminal,
	guest *models.Guest,
	inst *models.ProxmoxInstance,
	logger *log.Logger,
) error {
	label := barLabel(guest, inst, p.PublicEndpoint)
	if inst.ConnectionType == models.ConnectionTypeTermProxy {
		return connectTermProxy(term, guest, inst, logger, label)
	}
	return connectSSH(term, guest, inst, logger, label)
}

// defaults applied when sshd did not report a usable terminal.
const (
	defaultTerm   = "xterm-256color"
	defaultWidth  = 80
	defaultHeight = 24
)

// normalize fills in defaults for a terminal whose values are missing.
func (t *Terminal) normalize() {
	if t.Term == "" {
		t.Term = defaultTerm
	}
	if t.Width <= 0 {
		t.Width = defaultWidth
	}
	if t.Height <= 0 {
		t.Height = defaultHeight
	}
	if t.In == nil {
		t.In = os.Stdin
	}
	if t.Out == nil {
		t.Out = os.Stdout
	}
	if t.Err == nil {
		t.Err = os.Stderr
	}
}

// guestConsoleCmd returns the Proxmox command that opens the guest console.
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

// loadInstanceKey returns the PEM private key bytes for a Proxmox instance.
//
// In a session SSHKey is always set: the API resolved whichever key applies --
// the instance's own, or the deployment's from the volume -- and sent it
// inline, because this process can read neither the database nor a key file.
// SSHKeyPath is the fallback for a caller holding an instance straight from
// the database, and names the file in its error so a stale path says so
// rather than surfacing as an unexplained console failure.
func loadInstanceKey(inst *models.ProxmoxInstance) ([]byte, error) {
	if inst.SSHKey != "" {
		return []byte(inst.SSHKey), nil
	}
	if inst.SSHKeyPath == "" {
		return nil, fmt.Errorf(
			"instance %q has no ssh key: the session was given none, which "+
				"means the deployment has no key at %s",
			inst.Name, models.SSHKeyPath())
	}
	b, err := os.ReadFile(inst.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading proxmox key %s: %w", inst.SSHKeyPath, err)
	}
	return b, nil
}
