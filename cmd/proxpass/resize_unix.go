//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"proxpass/internal/console"
)

// watchResizes reports terminal size changes on resizes until the returned
// stop function is called.
//
// sshd delivers a window change to the session as SIGWINCH, which is where
// the SSH "window-change" request ends up. The signal does not exist on
// Windows, hence the build tag; proxpass only ever runs inside its Linux
// image, but the test matrix builds on every platform.
func watchResizes(fd int, resizes chan<- console.Size) (stop func()) {
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

	return func() {
		signal.Stop(sigwinch)
		close(done)
	}
}
