package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"time"

	"proxpass/internal/guesthelper"
)

// dispatch performs one operation and returns the reply header plus any data
// that belongs after it.
//
// A flat switch over the op set reads better than a map of closures would:
// every case is a few lines and the shape is the protocol itself.
func (s *session) dispatch(req *request) (resp guesthelper.Response, payload []byte) {
	h := &req.hdr
	switch h.Op {
	case guesthelper.OpHello:
		if h.Version != guesthelper.Version {
			return fail(fmt.Errorf(
				"protocol mismatch: client %d, helper %d",
				h.Version, guesthelper.Version)), nil
		}
		if h.IdleTimeoutSec > 0 {
			s.idle = time.Duration(h.IdleTimeoutSec) * time.Second
		}
		return guesthelper.Response{
			Version: guesthelper.Version,
			Arch:    runtime.GOARCH,
		}, nil

	case guesthelper.OpStat:
		fi, err := os.Lstat(h.Path)
		if err != nil {
			return fail(err), nil
		}
		return guesthelper.Response{Entries: []guesthelper.Entry{entryOf(fi)}}, nil

	case guesthelper.OpList:
		return s.list(h.Path), nil

	case guesthelper.OpRead:
		return s.read(h)

	case guesthelper.OpWrite:
		return s.write(h, req.payload), nil

	case guesthelper.OpMkdir:
		return okOr(os.Mkdir(h.Path, 0o755)), nil

	case guesthelper.OpRemove:
		return okOr(os.Remove(h.Path)), nil

	case guesthelper.OpRmdir:
		// Remove refuses a non-empty directory, which is the semantic
		// SFTP's Rmdir wants, so there is nothing extra to do here.
		return okOr(os.Remove(h.Path)), nil

	case guesthelper.OpRename:
		return okOr(os.Rename(h.Path, h.Target)), nil

	case guesthelper.OpSymlink:
		// Path is the target the link points AT; Target is the link to
		// create. The order matches the SFTP request and is the same
		// trap documented in internal/sftpserver.
		return okOr(os.Symlink(h.Path, h.Target)), nil

	case guesthelper.OpReadlink:
		dst, err := os.Readlink(h.Path)
		if err != nil {
			return fail(err), nil
		}
		return guesthelper.Response{Link: dst}, nil

	case guesthelper.OpChmod:
		return okOr(os.Chmod(h.Path, fs.FileMode(h.Mode).Perm())), nil

	case guesthelper.OpChown:
		// A negative id means "leave this half alone", which is what
		// os.Chown already does with -1.
		return okOr(os.Lchown(h.Path, int(h.UID), int(h.GID))), nil

	case guesthelper.OpChtimes:
		return okOr(os.Chtimes(h.Path,
			time.Unix(h.Atime, 0), time.Unix(h.Mtime, 0))), nil

	case guesthelper.OpTruncate:
		return okOr(os.Truncate(h.Path, h.Offset)), nil

	case guesthelper.OpQuit:
		// Handled by the caller, which stops the loop rather than
		// replying. Listed so the switch stays exhaustive.
		return guesthelper.Response{}, nil

	default:
		return fail(fmt.Errorf("unknown op %q", h.Op)), nil
	}
}

// list reads a directory.
//
// "." and ".." are never returned: os.ReadDir omits them already, and SFTP
// clients supply their own.
func (s *session) list(dir string) guesthelper.Response {
	des, err := os.ReadDir(dir)
	if err != nil {
		return fail(err)
	}
	entries := make([]guesthelper.Entry, 0, len(des))
	for _, de := range des {
		// Lstat rather than de.Info() is not needed: ReadDir already
		// returns un-followed entries, so a symlink reports as one.
		fi, infoErr := de.Info()
		if infoErr != nil {
			// One unreadable entry must not fail the whole listing,
			// matching the shell path's behavior.
			continue
		}
		entries = append(entries, entryOf(fi))
	}
	return guesthelper.Response{Entries: entries}
}

// read returns a byte range of a file.
//
// A negative Length means "to the end", which is how a whole-file read is
// asked for without the caller having to stat first.
func (s *session) read(h *guesthelper.Request) (resp guesthelper.Response, payload []byte) {
	f, err := os.Open(h.Path)
	if err != nil {
		return fail(err), nil
	}
	defer func() { _ = f.Close() }()

	if h.Offset > 0 {
		if _, err := f.Seek(h.Offset, io.SeekStart); err != nil {
			return fail(err), nil
		}
	}
	var r io.Reader = f
	if h.Length >= 0 {
		if h.Length > guesthelper.MaxPayload {
			return fail(fmt.Errorf(
				"read of %d bytes exceeds the %d limit",
				h.Length, guesthelper.MaxPayload)), nil
		}
		r = io.LimitReader(f, h.Length)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return fail(err), nil
	}
	return guesthelper.Response{}, data
}

// write puts bytes at an offset, creating the file if it is not there.
//
// O_TRUNC is applied only when the caller asks for it, which is the write
// that OPENS the file. SFTP writes arrive as (offset, data) pairs that need
// not be in order, so truncating on every one would discard everything an
// earlier chunk wrote.
//
// A zero-length payload is still a write: it is what creates an empty file,
// and returning early would reintroduce issue #104.
func (s *session) write(h *guesthelper.Request, payload []byte) guesthelper.Response {
	flags := os.O_WRONLY | os.O_CREATE
	if h.Trunc {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(h.Path, flags, 0o644)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteAt(payload, h.Offset); err != nil {
		return fail(err)
	}
	return guesthelper.Response{}
}

// entryOf converts an os.FileInfo to the wire form.
func entryOf(fi os.FileInfo) guesthelper.Entry {
	e := guesthelper.Entry{
		Name:  fi.Name(),
		Size:  fi.Size(),
		Mode:  uint32(fi.Mode()),
		Mtime: fi.ModTime().Unix(),
	}
	// Sys() is a *syscall.Stat_t on Linux, which is the only platform this
	// binary is built for. The check keeps it from panicking anywhere else.
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		e.UID, e.GID = st.Uid, st.Gid
	}
	return e
}

// okOr turns an error into a reply.
func okOr(err error) guesthelper.Response {
	if err == nil {
		return guesthelper.Response{}
	}
	return fail(err)
}

// fail classifies an error so the caller can map it back to an fs sentinel
// without matching on the message text.
func fail(err error) guesthelper.Response {
	return guesthelper.Response{Err: err.Error(), Errno: classify(err)}
}

// classify maps an error to its wire classification.
func classify(err error) guesthelper.Errno {
	switch {
	case err == nil:
		return guesthelper.ErrnoNone
	case errors.Is(err, fs.ErrNotExist):
		return guesthelper.ErrnoNotExist
	case errors.Is(err, fs.ErrPermission):
		return guesthelper.ErrnoPerm
	case errors.Is(err, fs.ErrExist):
		return guesthelper.ErrnoExist
	case errors.Is(err, syscall.ENOTEMPTY):
		return guesthelper.ErrnoNotEmpty
	case errors.Is(err, syscall.EISDIR):
		return guesthelper.ErrnoIsDir
	case errors.Is(err, syscall.ENOTDIR):
		return guesthelper.ErrnoNotDir
	default:
		return guesthelper.ErrnoOther
	}
}
