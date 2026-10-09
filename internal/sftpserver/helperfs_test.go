package sftpserver_test

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"proxpass/internal/guesthelper"
	"proxpass/internal/sftpserver"
)

// helperBuild compiles the guest helper once per test binary. Building it per
// test would dominate the run time.
var helperBuild struct {
	sync.Once
	path string
	out  string
	err  error
}

func buildGuestHelper(t *testing.T) string {
	t.Helper()
	helperBuild.Do(func() {
		dir, err := os.MkdirTemp("", "proxpass-helper-build")
		if err != nil {
			helperBuild.err = err
			return
		}
		out := filepath.Join(dir, "proxpass-helper")
		cmd := exec.Command("go", "build", "-o", out, "proxpass/cmd/proxpass-helper") //nolint:noctx // shared across tests.
		b, err := cmd.CombinedOutput()
		helperBuild.out = string(b)
		if err != nil {
			helperBuild.err = err
			return
		}
		helperBuild.path = out
	})
	if helperBuild.err != nil {
		t.Skipf("could not build the guest helper: %v\n%s", helperBuild.err, helperBuild.out)
	}
	return helperBuild.path
}

// newHelperFS starts the guest helper and returns it as an sftpserver.FS
// whose paths are relative to root.
func newHelperFS(t *testing.T, root string) sftpserver.FS {
	t.Helper()
	bin := buildGuestHelper(t)

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
	client, err := guesthelper.NewClient(rwPair{Reader: stdout, Writer: stdin}, time.Minute)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	return &rootedFS{Client: client, root: root}
}

// rootedFS makes a directory look like the filesystem root, which is what
// entering a container's mount namespace achieves in production.
//
// Clients send absolute paths because that is what a container's filesystem
// looks like to them; without this they would address the machine running the
// test.
type rootedFS struct {
	*guesthelper.Client
	root string
}

func (r *rootedFS) abs(p string) string { return filepath.Join(r.root, p) }

func (r *rootedFS) Stat(path string) (os.FileInfo, error)  { return r.Client.Stat(r.abs(path)) }
func (r *rootedFS) List(dir string) ([]os.FileInfo, error) { return r.Client.List(r.abs(dir)) }

func (r *rootedFS) ReadRangeTo(path string, offset, length int64, w io.Writer) error {
	return r.Client.ReadRangeTo(r.abs(path), offset, length, w)
}

func (r *rootedFS) WriteFrom(path string, src io.Reader) error {
	return r.Client.WriteFrom(r.abs(path), src)
}

func (r *rootedFS) WriteAtFrom(path string, offset int64, src io.Reader) error {
	return r.Client.WriteAtFrom(r.abs(path), offset, src)
}

func (r *rootedFS) Mkdir(path string) error  { return r.Client.Mkdir(r.abs(path)) }
func (r *rootedFS) Remove(path string) error { return r.Client.Remove(r.abs(path)) }
func (r *rootedFS) Rmdir(path string) error  { return r.Client.Rmdir(r.abs(path)) }

func (r *rootedFS) Rename(from, to string) error {
	return r.Client.Rename(r.abs(from), r.abs(to))
}

func (r *rootedFS) Symlink(target, linkPath string) error {
	// Only the LINK is rooted. A symlink's target is data: a container may
	// hold one pointing anywhere, and rewriting it would hide the case
	// most worth testing.
	return r.Client.Symlink(target, r.abs(linkPath))
}

func (r *rootedFS) Readlink(path string) (string, error) { return r.Client.Readlink(r.abs(path)) }

func (r *rootedFS) Chmod(path string, mode os.FileMode) error {
	return r.Client.Chmod(r.abs(path), mode)
}

func (r *rootedFS) Chown(path string, uid, gid int) error {
	return r.Client.Chown(r.abs(path), uid, gid)
}

func (r *rootedFS) Chtimes(path string, atime, mtime time.Time) error {
	return r.Client.Chtimes(r.abs(path), atime, mtime)
}

func (r *rootedFS) Truncate(path string, size int64) error {
	return r.Client.Truncate(r.abs(path), size)
}

type rwPair struct {
	io.Reader
	io.Writer
}
