package guesthelper

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
)

// binaries holds the helper, built for every architecture Proxmox runs on.
//
// # Why the binary ships inside the image
//
// The alternative -- a proxpass-helper package installed on each Proxmox
// node -- was rejected: it adds a deployment step to every node, and it
// introduces version skew between a proxpass that speaks protocol N and a
// node still holding protocol N-1. Shipping the helper with the thing that
// speaks to it makes a mismatch impossible by construction.
//
// The files are placeholders in a source checkout and are replaced by real
// binaries at image build time; see mise.toml's helpers task and the
// Dockerfile. A placeholder is detected at run time rather than at compile
// time, because `go test ./...' must work in a checkout that has never run
// the build task.
//
//go:embed bin/proxpass-helper-amd64 bin/proxpass-helper-arm64
var binaries embed.FS

// elfMagic is the first four bytes of any ELF executable.
//
// The check exists because the embedded files are placeholders unless the
// build staged real ones, and a placeholder pushed to a node would fail as
// "exec format error" on the far side -- a confusing place to learn about a
// build misconfiguration.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// ErrNoBinary reports that no usable helper is embedded for an architecture,
// which means the caller should fall back to the shell path.
var ErrNoBinary = errors.New("no helper binary embedded")

// Binary returns the helper for an architecture.
func Binary(arch Arch) ([]byte, error) {
	b, err := binaries.ReadFile("bin/proxpass-helper-" + string(arch))
	if err != nil {
		return nil, fmt.Errorf("%w for %s: %w", ErrNoBinary, arch, err)
	}
	if !bytes.HasPrefix(b, elfMagic) {
		return nil, fmt.Errorf(
			"%w for %s: the embedded file is a placeholder, not an executable"+
				" (the image build did not stage it)", ErrNoBinary, arch)
	}
	return b, nil
}

// BinaryReader returns the helper as a stream, for piping into a staging
// command without a second copy.
func BinaryReader(arch Arch) (io.Reader, error) {
	b, err := Binary(arch)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}
