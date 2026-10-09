package sftpserver_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"proxpass/internal/guesthelper"
	"proxpass/internal/sftpserver"
)

// TestHelperBackendServesSFTP drives a REAL sftp client against the helper
// backend, which is what proves the two satisfy each other: the interface
// compiles either way, but only an end-to-end run shows that the attributes,
// the chunking and the error codes all survive the round trip.
//
// The helper runs as an ordinary process here rather than inside a
// container. The namespace entry is nsenter's job and is covered against a
// real node; what this test covers is everything above it.
func TestHelperBackendServesSFTP(t *testing.T) {
	client, root := newHelperClient(t)

	// Upload, including a size that spans several protocol chunks.
	payload := bytes.Repeat([]byte("proxpass"), 200000) // 1.6 MB
	up := filepath.Join(root, "up.bin")
	f, err := client.Create(up)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The bytes must be identical: a PTY or a stray banner anywhere on the
	// path would corrupt them, which is the failure this guards.
	onDisk, err := os.ReadFile(up)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(onDisk) != sha256.Sum256(payload) {
		t.Fatalf("upload corrupted: %d bytes on disk, %d sent", len(onDisk), len(payload))
	}

	// Download it back.
	rf, err := client.Open(up)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, err := io.ReadAll(rf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = rf.Close()
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatalf("download corrupted: got %d bytes", len(got))
	}
}

// TestHelperBackendReportsOwner pins the fix: pkg/sftp reads the owner only
// from a *syscall.Stat_t, so a backend returning anything else silently
// tells every client the file is owned by 0:0.
func TestHelperBackendReportsOwner(t *testing.T) {
	client, root := newHelperClient(t)
	path := filepath.Join(root, "owned.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := client.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*sftp.FileStat)
	if !ok {
		t.Fatalf("Sys() = %T, want *sftp.FileStat", fi.Sys())
	}
	if wantUID := os.Getuid(); wantUID >= 0 && st.UID != uint32(wantUID) { //nolint:gosec // guarded non-negative.
		t.Errorf("UID = %d, want %d -- the owner did not survive the wire",
			st.UID, wantUID)
	}
}

// TestHelperBackendDirectoryOps covers the operations scp -r depends on.
//
// Each file is given CONTENT deliberately. A zero-byte Create never reaches
// WriteAt, so no backend creates the file at all -- see
// TestEmptyFileIsNotCreated, which pins that as the pre-existing behavior it
// is rather than letting this test quietly depend on it.
func TestHelperBackendDirectoryOps(t *testing.T) {
	client, root := newHelperClient(t)
	dir := filepath.Join(root, "d")
	if err := client.Mkdir(dir); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, name := range []string{"a", "b", "c"} {
		f, err := client.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := f.Write([]byte(name)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close %s: %v", name, err)
		}
	}
	entries, err := client.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	// Rename and remove, which scp -r and sftp both use.
	if err := client.Rename(filepath.Join(dir, "a"), filepath.Join(dir, "z")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := client.Remove(filepath.Join(dir, "z")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if entries, err = client.ReadDir(dir); err != nil || len(entries) != 2 {
		t.Fatalf("after remove: %d entries, err=%v", len(entries), err)
	}
}

// TestEmptyFileIsNotCreated documents a PRE-EXISTING limitation shared by
// both backends, so that a future change which fixes it is recognized as a
// fix rather than mistaken for a regression here.
//
// pkg/sftp's request server turns an Open-for-write into a Filewrite handler
// that is only consulted when bytes arrive. A client that creates a file and
// closes it without writing therefore produces no call at all, and nothing
// is created. `touch' over sftp does not work; scp of an empty file does not
// either. Fixing it means handling the open itself, which is a change to the
// shared handler and not to this backend.
func TestEmptyFileIsNotCreated(t *testing.T) {
	client, root := newHelperClient(t)
	path := filepath.Join(root, "empty.txt")
	f, err := client.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Skipf("empty files are now created (err=%v) -- this limitation "+
			"has been fixed and this test can go", err)
	}
}

// TestHelperBackendMissingFile pins that the sentinel survives two
// translations -- helper to client, then client to SFTP status.
func TestHelperBackendMissingFile(t *testing.T) {
	client, _ := newHelperClient(t)
	if _, err := client.Stat("/no/such/path/here"); !os.IsNotExist(err) {
		t.Errorf("err = %v, want a not-exist error", err)
	}
}

// newHelperClient wires a real sftp client to the helper backend.
func newHelperClient(t *testing.T) (client *sftp.Client, root string) {
	t.Helper()
	root = t.TempDir()
	sess := startLocalHelper(t)

	srvIn, cliOut := io.Pipe()
	cliIn, srvOut := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- sftpserver.Serve(rwc{Reader: srvIn, Writer: srvOut}, sess) }()

	client, err := sftp.NewClientPipe(cliIn, cliOut)
	if err != nil {
		t.Fatalf("sftp client: %v", err)
	}
	t.Cleanup(func() {
		// Same ordering as the shell-backend harness: close the
		// client's outbound pipe first or Close deadlocks.
		_ = cliOut.Close()
		<-done
		_ = srvOut.Close()
		_ = client.Close()
	})
	return client, root
}

// startLocalHelper builds and runs the helper, returning a client for it.
func startLocalHelper(t *testing.T) *guesthelper.Client {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "proxpass-helper")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "proxpass/cmd/proxpass-helper")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the helper: %v\n%s", err, out)
	}

	cmd := exec.CommandContext(t.Context(), bin, "serve")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	client, err := guesthelper.NewClient(
		readWriter{Reader: stdout, Writer: stdin}, time.Minute)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	return client
}

type readWriter struct {
	io.Reader
	io.Writer
}
