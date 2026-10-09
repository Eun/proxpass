// Package guesthelper speaks to a long-lived helper process running inside a
// container's namespaces.
//
// # Why a helper at all
//
// The path this replaced spent one SSH session, one nsenter and one shell PER
// FILESYSTEM OPERATION. An `scp -r' of five hundred small files therefore
// paid five hundred session handshakes, and every operation depended on the
// container shipping sh, cat, dd and stat. A container built FROM scratch has
// none of them and could not be served at all.
//
// The helper replaces that with one process per session: proxpass pushes a
// static binary to the node, starts it inside the container once, and then
// exchanges framed messages with it over the SSH session's stdin and stdout
// until the transfer is done.
//
// # Framing
//
// Every message is a 4-byte big-endian length followed by that many bytes of
// JSON. A request that carries file data appends the raw bytes immediately
// after the JSON, and the header's Len says how many. Replies do the same.
// Keeping the payload OUT of the JSON matters: base64 would cost a third more
// bytes and force whole-chunk buffering on both sides.
//
// The protocol is deliberately synchronous -- one reply per request, in order
// -- because the SFTP server above it already serializes its calls per file
// and a request id would buy nothing but bookkeeping.
package guesthelper

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version. The helper refuses a client that does not
// match, which turns a mismatched binary into a clear error at startup rather
// than a confusing failure once a transfer is under way.
//
// It is bumped whenever the wire format or the op set changes.
//
//	1  initial
//	2  Request.Trunc: the write that opens a file truncates it, so an
//	   empty file can be created (issue #104). A version-1 helper ignores
//	   the field and would leave a stale tail behind, which is a silent
//	   wrong answer rather than an error -- exactly what the handshake
//	   exists to prevent.
const Version = 2

// MaxFrame bounds a JSON header, so a corrupt length cannot make either side
// allocate without limit. Headers are small; payloads are NOT part of this.
const MaxFrame = 1 << 20

// MaxPayload bounds the data block attached to one message. SFTP chunks are
// at most 256 KiB in practice, so this leaves generous headroom while still
// refusing an absurd allocation.
const MaxPayload = 8 << 20

// Op names an operation. These mirror the methods of the sftpserver.FS
// interface, which is the surface the helper exists to serve.
type Op string

// The operations the helper understands.
const (
	OpHello    Op = "hello"
	OpStat     Op = "stat"
	OpList     Op = "list"
	OpRead     Op = "read"
	OpWrite    Op = "write"
	OpMkdir    Op = "mkdir"
	OpRemove   Op = "remove"
	OpRmdir    Op = "rmdir"
	OpRename   Op = "rename"
	OpSymlink  Op = "symlink"
	OpReadlink Op = "readlink"
	OpChmod    Op = "chmod"
	OpChown    Op = "chown"
	OpChtimes  Op = "chtimes"
	OpTruncate Op = "truncate"
	OpQuit     Op = "quit"
)

// Request is the header of a message from proxpass to the helper.
type Request struct {
	Op Op `json:"op"`
	// Path is the subject of the operation.
	Path string `json:"path,omitempty"`
	// Target is the second path, for rename and symlink.
	Target string `json:"target,omitempty"`
	// Offset is the byte offset for read and write.
	Offset int64 `json:"offset,omitempty"`
	// Length is how many bytes to read. A negative value means "to the end".
	Length int64 `json:"length,omitempty"`
	// Len is how many raw bytes follow this header.
	Len int64 `json:"len,omitempty"`
	// Trunc asks a write to create the file and discard anything already
	// in it. Only the write that OPENS a file sets it; the chunks that
	// follow must not, or each would discard its predecessor.
	Trunc bool `json:"trunc,omitempty"`
	// Mode is the permission bits for chmod.
	Mode uint32 `json:"mode,omitempty"`
	// UID and GID are for chown. A negative value leaves that half alone,
	// which is how SFTP asks to change only one of them.
	UID int64 `json:"uid,omitempty"`
	GID int64 `json:"gid,omitempty"`
	// Atime and Mtime are Unix seconds, for chtimes.
	Atime int64 `json:"atime,omitempty"`
	Mtime int64 `json:"mtime,omitempty"`
	// Version is sent with hello.
	Version int `json:"version,omitempty"`
	// IdleTimeoutSec, sent with hello, is how long the helper waits for a
	// request before giving up and exiting. Zero leaves the helper's own
	// default in place.
	IdleTimeoutSec int `json:"idle_timeout_sec,omitempty"`
}

// Response is the header of a message from the helper to proxpass.
type Response struct {
	// Err is empty on success. It carries the error TEXT; Errno carries the
	// classification, because a caller needs to tell "no such file" from
	// "permission denied" without matching on prose.
	Err   string `json:"err,omitempty"`
	Errno Errno  `json:"errno,omitempty"`
	// Len is how many raw bytes follow this header.
	Len int64 `json:"len,omitempty"`
	// Entries is the result of stat (one entry) and list (many).
	Entries []Entry `json:"entries,omitempty"`
	// Link is the result of readlink.
	Link string `json:"link,omitempty"`
	// Version and Arch are returned by hello, so a mismatch is caught
	// before any transfer starts.
	Version int    `json:"version,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

// Errno classifies a failure so the caller can map it to an fs sentinel
// without parsing a message.
type Errno string

// The classifications the helper reports.
const (
	ErrnoNone     Errno = ""
	ErrnoNotExist Errno = "notexist"
	ErrnoPerm     Errno = "perm"
	ErrnoExist    Errno = "exist"
	ErrnoNotEmpty Errno = "notempty"
	ErrnoIsDir    Errno = "isdir"
	ErrnoNotDir   Errno = "notdir"
	ErrnoOther    Errno = "other"
)

// Entry is one file's attributes, carrying the same fields the shell path
// parses out of `stat -c "%f %s %u %g %Y %n"'.
type Entry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	// Mode is Go's os.FileMode, not the raw system mode: the helper is a Go
	// program, so it already has the translation the shell path has to do
	// by hand from the hex %f field.
	Mode  uint32 `json:"mode"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Mtime int64  `json:"mtime"`
}

// ErrShortFrame reports a frame whose declared length exceeds the limits.
var ErrShortFrame = errors.New("frame too large")

// WriteMessage writes a length-prefixed JSON header and, if payload is not
// nil, the raw bytes after it.
//
// The caller is responsible for setting the header's Len to len(payload);
// this function does not reach into the header because Request and Response
// are distinct types and a generic one would cost reflection.
func WriteMessage(w io.Writer, header any, payload []byte) error {
	b, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("encoding header: %w", err)
	}
	if len(b) > MaxFrame {
		return ErrShortFrame
	}
	var prefix [4]byte
	// Bounded by MaxFrame just above, so the conversion cannot overflow.
	binary.BigEndian.PutUint32(prefix[:], uint32(len(b))) //nolint:gosec // see above.
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadHeader reads one length-prefixed JSON header into v.
func ReadHeader(r io.Reader, v any) error {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n > MaxFrame {
		return ErrShortFrame
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	if err := json.Unmarshal(buf, v); err != nil {
		return fmt.Errorf("decoding header: %w", err)
	}
	return nil
}

// ReadPayload reads n raw bytes that follow a header.
func ReadPayload(r io.Reader, n int64) ([]byte, error) {
	if n < 0 || n > MaxPayload {
		return nil, ErrShortFrame
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
