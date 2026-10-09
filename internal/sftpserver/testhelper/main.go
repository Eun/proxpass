// Command sftp-helper serves one directory over SFTP on stdin and stdout.
//
// It exists so that tests can drive the REAL scp and sftp clients against
// this package: both accept a program to speak the protocol to (scp -D,
// sftp -D), and expect it on stdin/stdout -- which is the same shape sshd
// gives `proxpass session' for a subsystem request.
//
// The guest helper is started as an ordinary local process and the directory
// stands in for a container's filesystem. Only the namespace entry is
// missing, which is nsenter's job and is covered against a real node; what a
// client exercises here is the actual protocol handling on both sides.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"proxpass/internal/guesthelper"
	"proxpass/internal/sftpserver"
)

func main() {
	// run() rather than inlining, so the deferred shutdown of the guest
	// helper actually happens: os.Exit does not run defers, and leaving
	// the helper behind would hold the test's pipes open.
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: sftp-helper <helper-binary> <directory>")
		return 2
	}
	helperBin, root := os.Args[1], os.Args[2]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, stop, err := startHelper(ctx, helperBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sftp-helper: %v\n", err)
		return 1
	}
	defer stop()

	if err := sftpserver.Serve(stdio{}, &rooted{Client: client, root: root}); err != nil {
		fmt.Fprintf(os.Stderr, "sftp-helper: %v\n", err)
		return 1
	}
	return 0
}

// startHelper runs the guest helper and returns a client for it.
func startHelper(ctx context.Context, bin string) (*guesthelper.Client, func(), error) {
	cmd := exec.CommandContext(ctx, bin, "serve") //nolint:gosec // the test supplies the path.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	client, err := guesthelper.NewClient(readWriter{Reader: stdout, Writer: stdin}, time.Minute)
	if err != nil {
		return nil, nil, err
	}
	return client, func() {
		_ = client.Close()
		_ = stdin.Close()
		_ = cmd.Wait()
	}, nil
}

// rooted makes the served directory look like the filesystem root, which is
// what entering a container's mount namespace would otherwise achieve.
//
// The client sends absolute paths because that is what a container's
// filesystem looks like to it; without this they would address the machine
// running the test.
type rooted struct {
	*guesthelper.Client
	root string
}

func (r *rooted) abs(p string) string { return filepath.Join(r.root, p) }

func (r *rooted) Stat(path string) (os.FileInfo, error)  { return r.Client.Stat(r.abs(path)) }
func (r *rooted) List(dir string) ([]os.FileInfo, error) { return r.Client.List(r.abs(dir)) }

func (r *rooted) ReadRangeTo(path string, offset, length int64, w io.Writer) error {
	return r.Client.ReadRangeTo(r.abs(path), offset, length, w)
}

func (r *rooted) WriteFrom(path string, src io.Reader) error {
	return r.Client.WriteFrom(r.abs(path), src)
}

func (r *rooted) WriteAtFrom(path string, offset int64, src io.Reader) error {
	return r.Client.WriteAtFrom(r.abs(path), offset, src)
}

func (r *rooted) Mkdir(path string) error  { return r.Client.Mkdir(r.abs(path)) }
func (r *rooted) Remove(path string) error { return r.Client.Remove(r.abs(path)) }
func (r *rooted) Rmdir(path string) error  { return r.Client.Rmdir(r.abs(path)) }

func (r *rooted) Rename(from, to string) error {
	return r.Client.Rename(r.abs(from), r.abs(to))
}

func (r *rooted) Symlink(target, linkPath string) error {
	// Only the LINK is placed inside the served directory. The target is
	// left as the client wrote it, because a symlink's target is data: a
	// container may legitimately hold one pointing anywhere, and rewriting
	// it would hide exactly the case worth testing.
	return r.Client.Symlink(target, r.abs(linkPath))
}

func (r *rooted) Readlink(path string) (string, error) { return r.Client.Readlink(r.abs(path)) }

func (r *rooted) Chmod(path string, mode os.FileMode) error {
	return r.Client.Chmod(r.abs(path), mode)
}

func (r *rooted) Chown(path string, uid, gid int) error {
	return r.Client.Chown(r.abs(path), uid, gid)
}

func (r *rooted) Chtimes(path string, atime, mtime time.Time) error {
	return r.Client.Chtimes(r.abs(path), atime, mtime)
}

func (r *rooted) Truncate(path string, size int64) error {
	return r.Client.Truncate(r.abs(path), size)
}

// stdio is the transport, matching how sshd hands over a subsystem.
type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error                { return nil }

type readWriter struct {
	io.Reader
	io.Writer
}
