package sftpserver_test

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// requireSCP skips when there is no scp binary to drive.
//
// The tests below use the REAL scp client rather than a hand-written protocol
// exchange, because the point is that an unmodified scp works. A version
// older than OpenSSH 9.0 would speak the legacy protocol instead of SFTP and
// not exercise this server at all, but every supported distribution is well
// past that.
func requireSCP(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("scp")
	if err != nil {
		t.Skip("scp is not installed")
	}
	return path
}

// runSCP drives the real scp client against our server.
//
// -D points scp at an "sftp server" program to speak to directly, instead of
// connecting over ssh. That is exactly the shape sshd gives us -- a subsystem
// on stdin/stdout -- so this exercises the server through a real client
// without needing an sshd, a key or a network.
//
// -O is deliberately NOT passed: its absence is what proves a plain scp works
// against this server, which is the entire reason SFTP is served rather than
// the legacy protocol.
func runSCP(t *testing.T, helper string, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"-D", helper}, args...)
	//nolint:gosec // driving the real scp client is the point of the test.
	cmd := exec.CommandContext(t.Context(), requireSCP(t), full...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// buildHelper compiles the test SFTP server that serves one directory.
//
// scp -D expects a program speaking SFTP on its stdin and stdout, so the
// helper is a tiny main() wrapping the same Serve() a session calls.
func buildHelper(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sftp-helper")
	cmd := exec.CommandContext(t.Context(),
		"go", "build", "-o", bin, "./internal/sftpserver/testhelper")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build the sftp helper (no toolchain?): %v\n%s", err, out)
	}
	// The guest helper is a separate binary that the test server starts
	// and speaks the protocol to, exactly as a session does on a node.
	guestBin := filepath.Join(t.TempDir(), "proxpass-helper")
	guestCmd := exec.CommandContext(t.Context(),
		"go", "build", "-o", guestBin, "./cmd/proxpass-helper")
	guestCmd.Dir = repoRoot(t)
	if out, err := guestCmd.CombinedOutput(); err != nil {
		t.Skipf("could not build the guest helper: %v\n%s", err, out)
	}

	// scp -D accepts a program path with no way to pass arguments, so the
	// paths are baked into a wrapper script.
	wrapper := filepath.Join(t.TempDir(), "run-helper")
	script := "#!/bin/sh\nexec " + bin + " " + guestBin + " " + root + "\n"
	// 0700: scp execs this, so it has to carry the execute bit.
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil { //nolint:gosec // must be executable.
		t.Fatalf("writing the wrapper: %v", err)
	}
	return wrapper
}

// repoRoot returns the module root, so `go build' can find the helper package
// regardless of which directory the test runs in.
func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "env", "GOMOD").Output()
	if err != nil {
		t.Skipf("could not locate the module root: %v", err)
	}
	return filepath.Dir(string(bytes.TrimSpace(out)))
}

// TestSCPUploadsAFileWithoutTheLegacyFlag is the headline claim: a plain scp,
// with no -O, copies a file in.
func TestSCPUploadsAFileWithoutTheLegacyFlag(t *testing.T) {
	requireShellTools(t)
	gfs, root := newFS(t)
	_ = gfs
	helper := buildHelper(t, root)

	src := filepath.Join(t.TempDir(), "payload.bin")
	payload := make([]byte, 128*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	out, err := runSCP(t, helper, src, "dummy:/landed.bin")
	if err != nil {
		t.Fatalf("scp failed: %v\n%s", err, out)
	}

	got, err := os.ReadFile(filepath.Join(root, "landed.bin"))
	if err != nil {
		t.Fatalf("the file did not land: %v\n%s", err, out)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("scp upload was not byte exact: got %d bytes, want %d",
			len(got), len(payload))
	}
}

// TestSCPDownloadsAFile covers the other direction.
func TestSCPDownloadsAFile(t *testing.T) {
	requireShellTools(t)
	_, root := newFS(t)
	helper := buildHelper(t, root)

	payload := make([]byte, 128*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "remote.bin"), payload, 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "fetched.bin")
	out, err := runSCP(t, helper, "dummy:/remote.bin", dst)
	if err != nil {
		t.Fatalf("scp failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("nothing was fetched: %v\n%s", err, out)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("scp download was not byte exact")
	}
}

// TestSCPRecursiveUploadBuildsTheTree is the case asked about specifically:
// scp -r has to create directories and place files inside them, which drives
// Mkdir, Setstat and several writes rather than one.
func TestSCPRecursiveUploadBuildsTheTree(t *testing.T) {
	requireShellTools(t)
	_, root := newFS(t)
	helper := buildHelper(t, root)

	// A tree with nesting, a dotfile and a file whose name needs quoting,
	// because those are what break a naive implementation.
	src := t.TempDir()
	tree := map[string]string{
		"top.txt":            "top level",
		"sub/nested.txt":     "one down",
		"sub/deeper/leaf.sh": "#!/bin/sh\necho hi\n",
		"sub/.hidden":        "dotfile",
		"sub/it's here.txt":  "quoting matters",
	}
	for rel, content := range tree {
		p := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("seeding %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("seeding %s: %v", rel, err)
		}
	}

	out, err := runSCP(t, helper, "-r", src, "dummy:/tree")
	if err != nil {
		t.Fatalf("scp -r failed: %v\n%s", err, out)
	}

	for rel, want := range tree {
		landed := filepath.Join(root, "tree", rel)
		got, readErr := os.ReadFile(landed)
		if readErr != nil {
			t.Errorf("%s did not land: %v", rel, readErr)
			continue
		}
		if string(got) != want {
			t.Errorf("%s content = %q, want %q", rel, got, want)
		}
	}
}

// TestSCPRecursiveDownloadFetchesTheTree is the reverse, which additionally
// needs directory listings to work: the client discovers what to fetch by
// reading the directory.
func TestSCPRecursiveDownloadFetchesTheTree(t *testing.T) {
	requireShellTools(t)
	_, root := newFS(t)
	helper := buildHelper(t, root)

	tree := map[string]string{
		"pull/a.txt":       "alpha",
		"pull/sub/b.txt":   "bravo",
		"pull/sub/c.bin":   "\x00\x01\x02binary\xff",
		"pull/sub/d/e.txt": "echo",
	}
	for rel, content := range tree {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("seeding %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("seeding %s: %v", rel, err)
		}
	}

	dst := t.TempDir()
	out, err := runSCP(t, helper, "-r", "dummy:/pull", dst)
	if err != nil {
		t.Fatalf("scp -r download failed: %v\n%s", err, out)
	}

	for rel, want := range tree {
		got, readErr := os.ReadFile(filepath.Join(dst, rel))
		if readErr != nil {
			t.Errorf("%s was not fetched: %v", rel, readErr)
			continue
		}
		if string(got) != want {
			t.Errorf("%s content = %q, want %q", rel, got, want)
		}
	}
}

// TestSCPPreservesModeWithDashP covers scp -p, which sends Setstat with the
// permissions and the timestamps rather than only writing content.
func TestSCPPreservesModeWithDashP(t *testing.T) {
	requireShellTools(t)
	_, root := newFS(t)
	helper := buildHelper(t, root)

	src := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(src, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	// The execute bit is the point: -p has to carry it across, and a mode
	// that only differs in the read bits would not prove anything.
	if err := os.Chmod(src, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	out, err := runSCP(t, helper, "-p", src, "dummy:/script.sh")
	if err != nil {
		t.Fatalf("scp -p failed: %v\n%s", err, out)
	}
	fi, err := os.Stat(filepath.Join(root, "script.sh"))
	if err != nil {
		t.Fatalf("the file did not land: %v\n%s", err, out)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("mode = %04o, want 0700", got)
	}
}
