package guesthelper

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"syscall"
	"time"
)

// ErrUnsupported reports that the helper could not be used for this
// container, so the caller should fall back to the shell path.
//
// It is a distinct error because falling back is CORRECT for it and wrong
// for anything else: a node that cannot run the helper still serves
// transfers through sh, but a transfer that failed halfway must not be
// silently retried by another route.
var ErrUnsupported = errors.New("helper unsupported")

// ErrNotRunning reports that the container is not running.
var ErrNotRunning = errors.New("container is not running")

// Client speaks the helper protocol over one stream.
//
// Every exchange is serialized: the protocol has no request ids, so two
// concurrent calls would read each other's replies. The SFTP server above
// does issue concurrent reads for one file, which is exactly why this lock
// is here rather than left to the caller.
type Client struct {
	mu     sync.Mutex
	rw     io.ReadWriter
	closed bool
}

// NewClient performs the handshake and returns a ready client.
//
// The handshake is what makes a version mismatch a startup error rather than
// a mid-transfer surprise, and it is also where the idle timeout is set, so
// the policy lives with the caller instead of being compiled into the helper.
func NewClient(rw io.ReadWriter, idleTimeout time.Duration) (*Client, error) {
	c := &Client{rw: rw}
	resp, _, err := c.call(&Request{
		Op:             OpHello,
		Version:        Version,
		IdleTimeoutSec: int(idleTimeout.Seconds()),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: handshake: %w", ErrUnsupported, err)
	}
	if resp.Version != Version {
		return nil, fmt.Errorf("%w: helper speaks protocol %d, we speak %d",
			ErrUnsupported, resp.Version, Version)
	}
	return c, nil
}

// call writes a request and reads its reply.
func (c *Client) call(req *Request, payload []byte) (Response, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Response{}, nil, errors.New("helper session is closed")
	}

	req.Len = int64(len(payload))
	if err := WriteMessage(c.rw, req, payload); err != nil {
		c.closed = true
		return Response{}, nil, err
	}
	var resp Response
	if err := ReadHeader(c.rw, &resp); err != nil {
		c.closed = true
		return Response{}, nil, err
	}
	var data []byte
	if resp.Len > 0 {
		d, err := ReadPayload(c.rw, resp.Len)
		if err != nil {
			c.closed = true
			return Response{}, nil, err
		}
		data = d
	}
	if resp.Err != "" {
		err := decode(&resp)
		return resp, data, err
	}
	return resp, data, nil
}

// decode turns a wire error back into something errors.Is can match, so the
// SFTP layer's existing translation keeps working unchanged.
func decode(resp *Response) error {
	msg := resp.Err
	switch resp.Errno {
	case ErrnoNotExist:
		return fmt.Errorf("%s: %w", msg, fs.ErrNotExist)
	case ErrnoPerm:
		return fmt.Errorf("%s: %w", msg, fs.ErrPermission)
	case ErrnoExist:
		return fmt.Errorf("%s: %w", msg, fs.ErrExist)
	case ErrnoNotEmpty:
		return fmt.Errorf("%s: %w", msg, syscall.ENOTEMPTY)
	case ErrnoIsDir:
		return fmt.Errorf("%s: %w", msg, syscall.EISDIR)
	case ErrnoNotDir:
		return fmt.Errorf("%s: %w", msg, syscall.ENOTDIR)
	case ErrnoNone, ErrnoOther:
		return errors.New(msg)
	default:
		return errors.New(msg)
	}
}

// Close tells the helper to exit.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	// Best effort: the stream is torn down by the caller regardless, and
	// the helper's idle timeout catches it even if this never arrives.
	_ = WriteMessage(c.rw, Request{Op: OpQuit}, nil)
	return nil
}

// Stat returns one file's attributes without following a final symlink.
func (c *Client) Stat(path string) (os.FileInfo, error) {
	resp, _, err := c.call(&Request{Op: OpStat, Path: path}, nil)
	if err != nil {
		return nil, err
	}
	if len(resp.Entries) != 1 {
		return nil, fmt.Errorf("stat %s: helper returned %d entries", path, len(resp.Entries))
	}
	return infoOf(resp.Entries[0]), nil
}

// List reads a directory.
func (c *Client) List(dir string) ([]os.FileInfo, error) {
	resp, _, err := c.call(&Request{Op: OpList, Path: dir}, nil)
	if err != nil {
		return nil, err
	}
	out := make([]os.FileInfo, 0, len(resp.Entries))
	for _, e := range resp.Entries {
		out = append(out, infoOf(e))
	}
	return out, nil
}

// ReadRangeTo streams length bytes from offset to w. A negative length means
// to the end of the file.
//
// A whole-file read is chunked rather than asked for in one message, because
// the protocol bounds a single payload and a large file would otherwise be
// refused -- and because holding an entire file in memory on both sides is
// not something a transfer should require.
func (c *Client) ReadRangeTo(path string, offset, length int64, w io.Writer) error {
	remaining := length
	for remaining != 0 {
		want := int64(chunkSize)
		if remaining > 0 && remaining < want {
			want = remaining
		}
		_, data, err := c.call(&Request{
			Op:     OpRead,
			Path:   path,
			Offset: offset,
			Length: want,
		}, nil)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			if _, err := w.Write(data); err != nil {
				return err
			}
			offset += int64(len(data))
			if remaining > 0 {
				remaining -= int64(len(data))
			}
		}
		// Short read means end of file, for both the bounded and the
		// unbounded case.
		if int64(len(data)) < want {
			return nil
		}
	}
	return nil
}

// chunkSize is how much one read or write message carries.
//
// 256 KiB matches the largest chunk an SFTP client asks for in practice, so
// a transfer costs one message per client request rather than several.
const chunkSize = 256 * 1024

// WriteFrom replaces a file's contents with what r yields, creating the file
// if it is not there.
//
// An EMPTY reader must still produce an empty file. The obvious shape --
// truncate, then stream the chunks -- does not: streaming nothing sends no
// write at all, so a path that does not yet exist stays missing. That is
// what made `touch' over sftp and scp of a zero-byte file silently do
// nothing (issue #104). The first write is therefore unconditional.
func (c *Client) WriteFrom(path string, r io.Reader) error {
	buf := make([]byte, chunkSize)
	n, err := r.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	// Unconditional, even for n == 0: this is what creates and truncates.
	if _, _, cerr := c.call(&Request{
		Op:     OpWrite,
		Path:   path,
		Offset: 0,
		Trunc:  true,
	}, buf[:n]); cerr != nil {
		return cerr
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return c.WriteAtFrom(path, int64(n), r)
}

// WriteAtFrom writes what r yields starting at offset.
func (c *Client) WriteAtFrom(path string, offset int64, r io.Reader) error {
	buf := make([]byte, chunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, _, cerr := c.call(&Request{
				Op:     OpWrite,
				Path:   path,
				Offset: offset,
			}, buf[:n]); cerr != nil {
				return cerr
			}
			offset += int64(n)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Mkdir creates a directory.
func (c *Client) Mkdir(path string) error { return c.simple(&Request{Op: OpMkdir, Path: path}) }

// Remove deletes a file.
func (c *Client) Remove(path string) error { return c.simple(&Request{Op: OpRemove, Path: path}) }

// Rmdir removes an empty directory.
func (c *Client) Rmdir(path string) error { return c.simple(&Request{Op: OpRmdir, Path: path}) }

// Rename moves a file.
func (c *Client) Rename(from, to string) error {
	return c.simple(&Request{Op: OpRename, Path: from, Target: to})
}

// Symlink creates linkPath pointing at target.
func (c *Client) Symlink(target, linkPath string) error {
	return c.simple(&Request{Op: OpSymlink, Path: target, Target: linkPath})
}

// Readlink returns a symlink's target.
func (c *Client) Readlink(path string) (string, error) {
	resp, _, err := c.call(&Request{Op: OpReadlink, Path: path}, nil)
	if err != nil {
		return "", err
	}
	return resp.Link, nil
}

// Chmod sets a file's permission bits.
func (c *Client) Chmod(path string, mode os.FileMode) error {
	return c.simple(&Request{Op: OpChmod, Path: path, Mode: uint32(mode.Perm())})
}

// Chown sets a file's owner. A negative id leaves that half unchanged.
func (c *Client) Chown(path string, uid, gid int) error {
	if uid < 0 && gid < 0 {
		return nil
	}
	return c.simple(&Request{Op: OpChown, Path: path, UID: int64(uid), GID: int64(gid)})
}

// Chtimes sets a file's access and modification times.
func (c *Client) Chtimes(path string, atime, mtime time.Time) error {
	return c.simple(&Request{
		Op:    OpChtimes,
		Path:  path,
		Atime: atime.Unix(),
		Mtime: mtime.Unix(),
	})
}

// Truncate sets a file's length.
func (c *Client) Truncate(path string, size int64) error {
	return c.simple(&Request{Op: OpTruncate, Path: path, Offset: size})
}

// simple issues a request whose reply carries nothing but success.
func (c *Client) simple(req *Request) error {
	_, _, err := c.call(req, nil)
	return err
}

// infoOf converts a wire entry to an os.FileInfo.
func infoOf(e Entry) os.FileInfo {
	return &entryInfo{e: e}
}

type entryInfo struct{ e Entry }

func (i *entryInfo) Name() string       { return i.e.Name }
func (i *entryInfo) Size() int64        { return i.e.Size }
func (i *entryInfo) Mode() os.FileMode  { return os.FileMode(i.e.Mode) }
func (i *entryInfo) ModTime() time.Time { return time.Unix(i.e.Mtime, 0) }
func (i *entryInfo) IsDir() bool        { return os.FileMode(i.e.Mode).IsDir() }

// Sys returns a *syscall.Stat_t carrying the owner.
//
// It must be exactly that type, not a convenient struct of our own:
// pkg/sftp's fileStatFromInfoOs does a type assertion to *syscall.Stat_t and
// silently drops the uid and gid when it fails, so an SFTP client would be
// told the file belongs to 0:0. The backend this replaced returned its own
// struct type and had exactly that bug -- see issue #103, which it was found
// by -- so the concrete type here is deliberate and must not be "tidied".
func (i *entryInfo) Sys() any {
	return &syscall.Stat_t{Uid: i.e.UID, Gid: i.e.GID}
}
