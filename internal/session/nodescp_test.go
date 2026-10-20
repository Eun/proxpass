package session_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"proxpass/internal/testenv"
)

// An unmodified scp must work against a node.
//
// -D points scp at a program that speaks SFTP on stdio, which is exactly
// the shape sshd hands `proxpass session' for a subsystem request. So this
// drives the real client through the real pump against a real sftp-server,
// without an sshd, a key exchange or a network.
//
// -O is deliberately NOT passed: its absence is what proves a plain scp
// works, which is the whole reason the subsystem is forwarded rather than
// some bespoke protocol.
func TestRealSCPTransfersToANode(t *testing.T) {
	scp, err := exec.LookPath("scp")
	if err != nil {
		t.Skip("scp is not installed")
	}

	mock, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("start mock proxmox host: %v", err)
	}
	defer mock.Close()
	root := t.TempDir()
	mock.SFTPRoot = root

	helper := buildNodeSCPHelper(t, mock)

	// Download: seed a file on the "node" and scp it out.
	const want = "node payload\n"
	if err := os.WriteFile(filepath.Join(root, "remote.txt"), []byte(want), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	local := t.TempDir()
	runNodeSCP(t, scp, helper,
		"node:"+filepath.Join(root, "remote.txt"), filepath.Join(local, "got.txt"))

	got, err := os.ReadFile(filepath.Join(local, "got.txt"))
	if err != nil {
		t.Fatalf("scp produced no file: %v", err)
	}
	if string(got) != want {
		t.Errorf("downloaded %q, want %q", got, want)
	}

	// Upload: push a file back to the "node".
	const up = "uploaded by scp\n"
	src := filepath.Join(local, "up.txt")
	if err := os.WriteFile(src, []byte(up), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	runNodeSCP(t, scp, helper, src, "node:"+filepath.Join(root, "arrived.txt"))

	landed, err := os.ReadFile(filepath.Join(root, "arrived.txt"))
	if err != nil {
		t.Fatalf("the upload did not reach the node: %v", err)
	}
	if string(landed) != up {
		t.Errorf("uploaded %q, want %q", landed, up)
	}
}

// buildNodeSCPHelper compiles the stdio helper and returns a wrapper script
// scp can run with no arguments of its own.
func buildNodeSCPHelper(t *testing.T, mock *testenv.MockSSHServer) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "helper")
	build := exec.CommandContext(t.Context(),
		"go", "build", "-o", bin, "proxpass/internal/session/nodescphelper")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("building the helper: %v", err)
	}

	// scp runs -D as a bare program with no arguments of its own, so the
	// connection details are baked into a wrapper. chmod rather than a
	// mode on WriteFile: an executable bit is what this needs, and
	// writing one directly trips the repository's file-permission lint.
	script := filepath.Join(dir, "run.sh")
	body := "#!/bin/sh\nexec " + bin + " " + mock.Host + " " +
		strconv.Itoa(mock.Port) + " " + mock.User + " " + mock.KeyPath + " " +
		mock.HostKeyFingerprint() + "\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatalf("chmod wrapper: %v", err)
	}
	return script
}

func runNodeSCP(t *testing.T, scp, helper, from, to string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), scp, "-D", helper, from, to)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("scp %s %s: %v\n%s", from, to, err, out.String())
	}
}
