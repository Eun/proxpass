// Package sftpserver serves the SFTP protocol against a Proxmox container.
//
// This is what makes "scp file.txt ct100@host:/tmp/" and "sftp ct100@host"
// work. Both are the same protocol: since OpenSSH 9.0 scp speaks SFTP by
// default, and it does NOT fall back to the old scp protocol if the subsystem
// is missing -- so serving SFTP is what makes a plain scp work, and serving
// only the legacy protocol would have required every user to pass -O.
//
// # Where the bytes go
//
// Nothing is written on the Proxmox node. Each request becomes a command run
// inside the container's namespaces, and file content streams through that
// command's stdin or stdout. See internal/guesthelper for why entering the
// namespace -- rather than prefixing /proc/<pid>/root onto the path -- is the
// only safe way to do this.
//
// # Errors
//
// sshd discards a subsystem's stderr, so an error written there is invisible:
// the user sees "Connection closed" and nothing else. Every failure here must
// therefore travel as an SFTP status packet, which is what returning an error
// from a handler does.
package sftpserver

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"sync"
	"time"

	"github.com/pkg/sftp"

	"proxpass/internal/guesthelper"
)

// FS is the filesystem of the container being served.
//
// It is satisfied by guesthelper.Session, which talks to a long-lived helper
// process inside the container. The interface is declared HERE, where it is
// consumed, so the tests can substitute a directory-rooted implementation
// without the production one knowing.
type FS interface {
	Stat(path string) (os.FileInfo, error)
	List(dir string) ([]os.FileInfo, error)
	ReadRangeTo(path string, offset, length int64, w io.Writer) error
	// WriteFrom replaces a file's contents, creating it if needed. It is
	// distinct from WriteAtFrom because it also TRUNCATES, which is what
	// establishes a file on a client's first write.
	WriteFrom(path string, r io.Reader) error
	WriteAtFrom(path string, offset int64, r io.Reader) error
	Mkdir(path string) error
	Remove(path string) error
	Rmdir(path string) error
	Rename(from, to string) error
	Symlink(target, linkPath string) error
	Readlink(path string) (string, error)
	Chmod(path string, mode os.FileMode) error
	Chown(path string, uid, gid int) error
	Chtimes(path string, atime, mtime time.Time) error
	Truncate(path string, size int64) error
}

// Handler serves SFTP requests against one container.
type Handler struct {
	FS FS
}

// Serve runs the SFTP protocol over rwc until the client disconnects.
func Serve(rwc io.ReadWriteCloser, gfs FS) error {
	h := &Handler{FS: gfs}
	srv := sftp.NewRequestServer(rwc, sftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	})
	if err := srv.Serve(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// Fileread returns a reader for a download.
//
// The returned io.ReaderAt is asked for arbitrary ranges, because an SFTP
// client reads a file in parallel chunks. Each ReadAt becomes one ranged read
// inside the container.
func (h *Handler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	// Stat first so a missing file is reported as such here, rather than as
	// a read failure on the first chunk.
	if _, err := h.FS.Stat(r.Filepath); err != nil {
		return nil, translate(err)
	}
	return &remoteFile{fs: h.FS, path: r.Filepath}, nil
}

// Filewrite returns a writer for an upload.
//
// SFTP writes arrive as (offset, data) pairs and need not be in order, so the
// writer cannot assume a stream. It creates the file on first use and then
// writes each chunk at its offset.
func (h *Handler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	return &remoteFile{fs: h.FS, path: r.Filepath, forWriting: true}, nil
}

// Filecmd performs an operation with no data transfer.
func (h *Handler) Filecmd(r *sftp.Request) error {
	switch r.Method {
	case "Setstat":
		return translate(h.setstat(r))
	case "Rename", "PosixRename":
		return translate(h.FS.Rename(r.Filepath, r.Target))
	case "Rmdir":
		return translate(h.FS.Rmdir(r.Filepath))
	case "Remove":
		return translate(h.FS.Remove(r.Filepath))
	case "Mkdir":
		return translate(h.FS.Mkdir(r.Filepath))
	case "Symlink":
		// Note the argument order: for SFTP, Filepath is the TARGET the
		// link points at and Target is the link to create. Reversing them
		// creates a link nobody asked for, pointing at the wrong place.
		return translate(h.FS.Symlink(r.Filepath, r.Target))
	case "Link":
		return fmt.Errorf("hard links: %w", sftp.ErrSSHFxOpUnsupported)
	default:
		return fmt.Errorf("%s: %w", r.Method, sftp.ErrSSHFxOpUnsupported)
	}
}

// setstat applies whichever attributes the client sent.
//
// A client sends only the attributes it wants changed, so each is applied
// independently and an unset one is left alone. scp -p sends mtime/atime;
// scp without -p sends the mode.
func (h *Handler) setstat(r *sftp.Request) error {
	attrs := r.Attributes()
	flags := r.AttrFlags()

	if flags.Size {
		// The size is a uint64 on the wire. Converting it blindly would
		// wrap into a negative length for a value above 2^63, which
		// truncate would then reject with something unhelpful -- or worse,
		// accept. A client has no legitimate reason to send one.
		if attrs.Size > math.MaxInt64 {
			return fmt.Errorf("size %d is out of range", attrs.Size)
		}
		if err := h.FS.Truncate(r.Filepath, int64(attrs.Size)); err != nil {
			return err
		}
	}
	if flags.Permissions {
		if err := h.FS.Chmod(r.Filepath, attrs.FileMode().Perm()); err != nil {
			return err
		}
	}
	if flags.UidGid {
		if err := h.FS.Chown(r.Filepath, int(attrs.UID), int(attrs.GID)); err != nil {
			return err
		}
	}
	if flags.Acmodtime {
		if err := h.FS.Chtimes(r.Filepath,
			attrs.AccessTime(), attrs.ModTime()); err != nil {
			return err
		}
	}
	return nil
}

// Filelist serves directory listings and single-path stats.
func (h *Handler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	switch r.Method {
	case "List":
		infos, err := h.FS.List(r.Filepath)
		if err != nil {
			return nil, translate(err)
		}
		return listerAt(infos), nil

	case "Stat", "Lstat":
		fi, err := h.FS.Stat(r.Filepath)
		if err != nil {
			return nil, translate(err)
		}
		return listerAt{fi}, nil

	case "Readlink":
		target, err := h.FS.Readlink(r.Filepath)
		if err != nil {
			return nil, translate(err)
		}
		// Readlink is answered with a one-entry listing whose NAME is the
		// link target, which is how this library models the reply.
		return listerAt{&linkTarget{name: target}}, nil

	default:
		return nil, fmt.Errorf("%s: %w", r.Method, sftp.ErrSSHFxOpUnsupported)
	}
}

// listerAt adapts a slice of os.FileInfo to sftp.ListerAt.
type listerAt []os.FileInfo

// ListAt copies entries starting at offset, reporting io.EOF when it reaches
// the end. Returning (n>0, io.EOF) together is correct and expected here.
func (l listerAt) ListAt(out []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(out, l[offset:])
	if offset+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

// linkTarget is an os.FileInfo that carries only a name, used to answer
// Readlink.
type linkTarget struct{ name string }

func (l *linkTarget) Name() string       { return l.name }
func (l *linkTarget) Size() int64        { return 0 }
func (l *linkTarget) Mode() os.FileMode  { return os.ModeSymlink }
func (l *linkTarget) ModTime() time.Time { return time.Time{} }
func (l *linkTarget) IsDir() bool        { return false }
func (l *linkTarget) Sys() any           { return nil }

// remoteFile is one open file inside the container.
//
// It holds no handle on the far side: each ReadAt or WriteAt is its own
// command. That costs a round trip per chunk, and buys statelessness -- there
// is no descriptor to leak if the client vanishes mid-transfer, and a
// container restart cannot leave this pointing at a stale file.
type remoteFile struct {
	fs   FS
	path string

	forWriting bool

	mu sync.Mutex
	// created records that the file has been created, so the first write
	// truncates and later ones do not.
	created bool
}

// ReadAt reads one chunk of the file.
func (f *remoteFile) ReadAt(p []byte, off int64) (int, error) {
	var buf writeCounter
	buf.to = p
	if err := f.fs.ReadRangeTo(f.path, off, int64(len(p)), &buf); err != nil {
		return buf.n, translate(err)
	}
	if buf.n < len(p) {
		// Short read means end of file, which io.ReaderAt reports as EOF
		// alongside the bytes it did manage.
		return buf.n, io.EOF
	}
	return buf.n, nil
}

// WriteAt writes one chunk of the file.
//
// The first write creates and truncates; later writes go to their offset and
// keep what is already there. A client that writes out of order therefore
// still gets the right file, as long as its first write is the one that
// establishes the file -- which is what every client does.
func (f *remoteFile) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	r := bytesReader(p)
	if !f.created && off == 0 {
		if err := f.fs.WriteFrom(f.path, r); err != nil {
			return 0, translate(err)
		}
		f.created = true
		return len(p), nil
	}
	// Any other offset, or a second write, has to preserve the rest of the
	// file. Creating it first if necessary, because a client may begin at a
	// non-zero offset.
	if !f.created {
		if err := f.fs.WriteFrom(f.path, emptyReader{}); err != nil {
			return 0, translate(err)
		}
		f.created = true
	}
	if err := f.fs.WriteAtFrom(f.path, off, r); err != nil {
		return 0, translate(err)
	}
	return len(p), nil
}

// Close satisfies the io.Closer the request server looks for. There is no
// remote handle to release.
func (f *remoteFile) Close() error { return nil }

// writeCounter fills a fixed buffer and counts what arrived, so a short read
// can be distinguished from a full one.
type writeCounter struct {
	to []byte
	n  int
}

func (w *writeCounter) Write(p []byte) (int, error) {
	n := copy(w.to[w.n:], p)
	w.n += n
	if n < len(p) {
		// More arrived than was asked for. Report it rather than silently
		// dropping bytes, since it means the range command misbehaved.
		return n, io.ErrShortBuffer
	}
	return n, nil
}

// emptyReader is an io.Reader with no content, used to create a file.
type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

// bytesReader returns an io.Reader over p without copying it.
func bytesReader(p []byte) io.Reader { return &sliceReader{p: p} }

type sliceReader struct {
	p []byte
	i int
}

func (r *sliceReader) Read(out []byte) (int, error) {
	if r.i >= len(r.p) {
		return 0, io.EOF
	}
	n := copy(out, r.p[r.i:])
	r.i += n
	return n, nil
}

// translate maps an error onto the SFTP status code a client understands.
//
// Without this every failure becomes "failure", and an sftp client prints
// that instead of "No such file". The mapping is on the sentinels the two
// backends produce; both are listed because either may be serving.
func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return sftp.ErrSSHFxNoSuchFile
	case errors.Is(err, fs.ErrPermission):
		return sftp.ErrSSHFxPermissionDenied
	case errors.Is(err, guesthelper.ErrNotRunning):
		// There is no SFTP status for "the machine is off", and failure
		// with a message is what a client will show the user.
		return fmt.Errorf("container is not running")
	default:
		return err
	}
}
