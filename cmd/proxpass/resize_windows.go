//go:build windows

package main

import "proxpass/internal/console"

// watchResizes is a no-op on Windows: there is no SIGWINCH, and proxpass
// sessions only ever run inside the Linux image. This exists so the package
// still builds on the Windows leg of the test matrix.
func watchResizes(_ int, _ chan<- console.Size) (stop func()) {
	return func() {}
}
