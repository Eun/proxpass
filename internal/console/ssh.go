package console

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	gossh "golang.org/x/crypto/ssh"

	"proxpass/internal/models"
	"proxpass/internal/sshhostkey"
)

// connectSSH attaches the terminal to a guest console by SSHing into the
// Proxmox host and running "pct enter" / "qm terminal" there.
//
// This is the outbound half of proxpass: proxpass is an SSH *client* here.
// The inbound half is handled by sshd.
func connectSSH(
	term *Terminal,
	guest *models.Guest,
	inst *models.ProxmoxInstance,
	sshKey string,
	logger *log.Logger,
	label string,
) error {
	cmd, err := guestConsoleCmd(guest)
	if err != nil {
		return err
	}
	return runSSHConsole(term, inst, sshKey, logger, label, "guest "+strconv.Quote(guest.Name), cmd)
}

// connectNodeSSH attaches the terminal to a shell on the Proxmox node.
//
// The same transport as a guest console, with no command: the remote end
// starts the login shell for inst.SSHUser. Everything else -- the PTY, the
// status bar's reserved row, resize forwarding, the Ctrl+A X escape hatch --
// is wanted here for exactly the reasons it is wanted for a guest, which is
// why this shares runSSHConsole rather than reimplementing it.
//
// Note there is no termproxy counterpart. ConsoleTransport decides how a
// GUEST console is attached -- through the Proxmox websocket or by running
// pct enter over SSH -- and says nothing about the node, which is reachable
// only over SSH either way. The same reasoning applies to file transfer,
// which likewise does not consult it.
func connectNodeSSH(
	term *Terminal,
	inst *models.ProxmoxInstance,
	sshKey string,
	logger *log.Logger,
	label string,
) error {
	return runSSHConsole(term, inst, sshKey, logger, label, "node "+strconv.Quote(inst.Name), "")
}

// startRemote begins the remote end of a console session.
//
// An empty cmd means a shell: the node path wants whatever login shell the
// remote user has, which is what Shell() asks for. A guest console names
// the command that enters it instead.
func startRemote(session *gossh.Session, cmd string) error {
	if cmd == "" {
		if err := session.Shell(); err != nil {
			return fmt.Errorf("starting remote shell: %w", err)
		}
		return nil
	}
	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("starting command %q: %w", cmd, err)
	}
	return nil
}

// runSSHConsole is the shared body of connectSSH and connectNodeSSH.
//
// cmd is what to run on the Proxmox host, or "" to start the remote login
// shell -- which is the difference between entering a guest and getting a
// shell on the node itself. target names the thing being connected to, and
// is used only in log lines.
func runSSHConsole(
	term *Terminal,
	inst *models.ProxmoxInstance,
	sshKey string,
	logger *log.Logger,
	label string,
	target string,
	cmd string,
) error {
	term.normalize()

	keyBytes, err := loadInstanceKey(inst, sshKey)
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
		HostKeyCallback: sshhostkey.Callback(inst.SSHHost, inst.SSHFingerprints, inst.InsecureSSH),
		// Bound the connect + handshake so a down node fails the acting user in
		// seconds instead of hanging their session forever.
		Timeout: sshDialTimeout,
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

	// Reserve the bottom row for the status bar and request a PTY one row
	// shorter, so the remote end never writes into it. guestOut is where
	// its output goes: the bar's observer when there is a bar, the
	// terminal directly when there is not.
	bar, guestOut, guestRows := startBar(term, label, EscapeHint)
	if bar != nil {
		defer bar.Stop()
	} else {
		// No bar clears the screen for us, so do it here -- otherwise a
		// quiet serial console draws its first line at the cursor's current
		// row (e.g. row 80). See clearScreenNoBar.
		clearScreenNoBar(term)
	}
	// Under a PTY, stderr and stdout are the same device. With a bar, stderr
	// has to take the same write lock as everything else; without one there
	// is nothing to serialize against.
	guestErr := term.Err
	if bar != nil {
		guestErr = bar.serializedWriter(term.Err)
	}

	// pct enter and qm terminal both misbehave without a PTY, and an
	// interactive shell on the node needs one for the same reasons.
	if err := session.RequestPty(term.Term, guestRows, term.Width, gossh.TerminalModes{}); err != nil {
		return fmt.Errorf("requesting remote pty: %w", err)
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
	if err := startRemote(session, cmd); err != nil {
		return err
	}

	done := make(chan struct{})
	var wg sync.WaitGroup

	// escaped is closed when the user presses Ctrl+A X, so the session is
	// torn down without waiting for the guest to exit on its own.
	escaped := make(chan struct{})
	var escapeOnce sync.Once

	// Forward terminal resizes for as long as the session lives.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			case size, ok := <-term.Resizes:
				if !ok {
					return
				}
				// Tell the guest about the height it actually has, and
				// repaint the bar at its new position. shox resizes without
				// redrawing (terminal.go:112-130), which leaves a stale bar
				// on screen until its next idle tick.
				rows := size.Height
				if bar != nil {
					rows = bar.Resize(size.Width, size.Height)
				}
				_ = session.WindowChange(rows, size.Width)
			}
		}
	}()

	// stdin is copied in a goroutine that is deliberately not waited on: a
	// read from the terminal blocks until the user types, so waiting for it
	// would hang the session teardown after the guest exits.
	go func() {
		src := newEscapeReader(term.In, func() {
			escapeOnce.Do(func() { close(escaped) })
		})
		_, _ = io.Copy(remoteStdin, src)
		_ = remoteStdin.Close()
	}()

	// Terminate the session when the user escapes.
	//
	// Closing stdin above is not sufficient by itself. A healthy shell does
	// exit on stdin EOF, but the escape hatch exists precisely for remote
	// ends that are not healthy -- a wedged process, a full-screen application,
	// or a shell with IGNOREEOF set will sit there and session.Wait would
	// block until it exited on its own.
	//
	// Closing the channel is the part that reliably ends it. The signal is
	// sent first as a courtesy so the remote command can tidy up, but it is
	// best-effort: OpenSSH's sshd does not implement the "signal" channel
	// request, so against a real Proxmox host this is usually a no-op.
	go func() {
		select {
		case <-done:
		case <-escaped:
			logger.Printf("console: %s disconnected by Ctrl+A X", target)
			_ = session.Signal(gossh.SIGTERM)
			_ = session.Close()
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(guestOut, remoteStdout)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Through guestErr, not term.Err directly: under a PTY both streams
		// are the same device, so stderr is a third writer competing with
		// the guest's stdout and the bar for one terminal. Writing it
		// unsynchronized could split a bar repaint or a guest escape
		// sequence in half.
		_, _ = io.Copy(guestErr, remoteStderr)
	}()

	err = session.Wait()
	close(done)
	_ = remoteStdin.Close()
	wg.Wait()

	// Escaping is a deliberate disconnect, so it is not an error even though
	// it forced the remote command down.
	select {
	case <-escaped:
		return nil
	default:
	}

	// An interactive console almost always ends with the remote command
	// exiting non-zero or being killed by a signal; that is an ordinary
	// disconnect rather than a proxpass failure.
	var exitErr *gossh.ExitError
	var missingErr *gossh.ExitMissingError
	if errors.As(err, &exitErr) || errors.As(err, &missingErr) {
		logger.Printf("console: %s session ended: %v", target, err)
		return nil
	}
	return err
}
