package guesthelper_test

import (
	"errors"
	"testing"

	"proxpass/internal/guesthelper"
)

// elfMachine is the e_machine field: the architecture an ELF file is for.
const (
	elfMachineX8664   = 0x3e
	elfMachineAArch64 = 0xb7
)

// TestEmbeddedBinariesMatchTheirArch is the test that catches the mistake
// this whole mechanism exists to prevent: shipping an amd64 helper to an
// arm64 node, which fails on the node as "exec format error" -- far from
// anything that would point at the build.
//
// It is skipped in a plain checkout, where the committed files are
// placeholders. CI runs `mise run helpers' first, so it does run there.
func TestEmbeddedBinariesMatchTheirArch(t *testing.T) {
	for _, tc := range []struct {
		arch    guesthelper.Arch
		machine byte
	}{
		{guesthelper.ArchAMD64, elfMachineX8664},
		{guesthelper.ArchARM64, elfMachineAArch64},
	} {
		b, err := guesthelper.Binary(tc.arch)
		if errors.Is(err, guesthelper.ErrNoBinary) {
			t.Skipf("no real binary staged for %s: run `mise run helpers'", tc.arch)
		}
		if err != nil {
			t.Fatalf("Binary(%s): %v", tc.arch, err)
		}
		// e_machine is a little-endian half at offset 18.
		if got := b[18]; got != tc.machine {
			t.Errorf("%s binary has e_machine 0x%02x, want 0x%02x"+
				" -- the wrong architecture is embedded", tc.arch, got, tc.machine)
		}
	}
}

// TestPlaceholderIsRefused pins that a build which forgot to stage the
// binaries fails HERE, with an explanation, rather than on a Proxmox node.
func TestPlaceholderIsRefused(t *testing.T) {
	if _, err := guesthelper.Binary("riscv64"); !errors.Is(err, guesthelper.ErrNoBinary) {
		t.Errorf("err = %v, want ErrNoBinary for an architecture we do not build", err)
	}
}
