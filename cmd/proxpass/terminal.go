package main

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"proxpass/internal/console"
)

// currentTerminal describes the terminal sshd handed this process and returns
// a restore function that must be called before exiting.
//
// sshd has already allocated the PTY and exported TERM, so there is no
// pty-req to parse. Raw mode is required for an interactive console: without
// it the local line discipline would echo input and buffer until newline,
// which breaks full-screen guest applications. Resizes arrive as SIGWINCH
// rather than as SSH "window-change" requests.
func currentTerminal() (t *console.Terminal, restore func()) {
	t = &console.Terminal{
		In:   os.Stdin,
		Out:  os.Stdout,
		Err:  os.Stderr,
		Term: os.Getenv("TERM"),
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// No PTY: a non-interactive command such as "guest ls". Leave the
		// streams alone and report no resizes.
		return t, func() {}
	}

	if w, h, err := term.GetSize(fd); err == nil {
		t.Width, t.Height = w, h
	}

	state, err := term.MakeRaw(fd)
	if err != nil {
		// Without raw mode the session still works for line-oriented use.
		return t, func() {}
	}

	resizes := make(chan console.Size, 1)
	t.Resizes = resizes

	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-sigwinch:
				w, h, err := term.GetSize(fd)
				if err != nil {
					continue
				}
				select {
				case resizes <- console.Size{Width: w, Height: h}:
				default:
					// A resize is already queued; the newest size will be
					// picked up by the next read.
				}
			}
		}
	}()

	var restored bool
	return t, func() {
		if restored {
			return
		}
		restored = true
		signal.Stop(sigwinch)
		close(done)
		_ = term.Restore(fd, state)
	}
}
