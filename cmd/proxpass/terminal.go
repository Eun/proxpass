package main

import (
	"os"

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

	// Past this point the terminal no longer translates "\n" into "\r\n", so
	// proxpass's own output has to do it itself; see Terminal.UIOut.
	t.Raw = true

	resizes := make(chan console.Size, 1)
	t.Resizes = resizes
	stopResizes := watchResizes(fd, resizes)

	var restored bool
	return t, func() {
		if restored {
			return
		}
		restored = true
		stopResizes()
		_ = term.Restore(fd, state)
	}
}
