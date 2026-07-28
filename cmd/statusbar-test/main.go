// statusbar-test runs a command under a persistent status bar.
//
// Usage:
//
//	statusbar-test --text "text" --hint "hint" /bin/sh [args...]
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"proxpass/pkg/statusbar"

	"github.com/creack/pty"
	"golang.org/x/term"
)

func main() {
	// Parse --text and --hint flags manually so we can keep the rest as the command.
	args := os.Args[1:]
	text := "statusbar-test"
	hint := "Ctrl+A X: exit"
	for len(args) >= 2 {
		switch args[0] {
		case "--text":
			text = args[1]
			args = args[2:]
		case "--hint":
			hint = args[1]
			args = args[2:]
		default:
			goto done
		}
	}
done:
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: statusbar-test [--text TEXT] [--hint HINT] <command> [args...]")
		os.Exit(1)
	}

	// Get current terminal size.
	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		cols, rows = 80, 24
	}

	// Create the status bar writing to stdout.
	sb := statusbar.New(os.Stdout,
		statusbar.WithText("statusbar-test", text),
		statusbar.WithHint(hint),
	)
	guestRows := sb.Setup(cols, rows)

	// Start the child command under a PTY sized to guestRows (reserve last row).
	cmd := exec.Command(args[0], args[1:]...)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(guestRows),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pty.Start: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = ptmx.Close() }()

	// Put stdin into raw mode.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "MakeRaw: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	// Handle SIGWINCH: resize pty and update status bar.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			c, r, e := term.GetSize(int(os.Stdout.Fd()))
			if e != nil {
				continue
			}
			gr := sb.Resize(c, r)
			_ = pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(c), Rows: uint16(gr)})
		}
	}()

	// PTY → stdout via status bar writer (redraws bar after every chunk).
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		w := sb.Writer()
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	// stdin → PTY (with Ctrl+A X intercept).
	go func() {
		buf := make([]byte, 256)
		pending := false
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				i := 0
				out := buf[:n]
				if pending {
					pending = false
					if out[0] == 'X' || out[0] == 'x' {
						// Ctrl+A X: exit cleanly.
						_ = cmd.Process.Signal(syscall.SIGTERM)
						return
					}
				}
				for i < len(out) {
					if out[i] == 0x01 { // Ctrl+A
						pending = true
						out = append(out[:i], out[i+1:]...)
					} else {
						i++
					}
				}
				if len(out) > 0 {
					_, _ = ptmx.Write(out)
				}
			}
			if err != nil {
				break
			}
		}
	}()

	<-done
	_ = cmd.Wait()
	sb.Clear()
	sb.Teardown()
	_ = term.Restore(int(os.Stdin.Fd()), oldState)
}
