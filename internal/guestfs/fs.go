package guestfs

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"
)

// Runner runs one command on the Proxmox node.
//
// An implementation opens a fresh SSH session per call, because a session
// carries exactly one command and one set of streams. stdin is read to EOF by
// commands that consume it, so a caller streaming an upload closes it to
// signal the end.
//
// IMPORTANT: an implementation must NOT request a PTY. lxc-attach, which
// nsenter reaches, turns on terminal handling when ANY of the three standard
// descriptors is a terminal, and that translates newlines -- silently
// corrupting every binary transfer. See the FS doc comment.
type Runner interface {
	// Run executes cmd. stdin may be nil. stdout may be nil to discard.
	// It returns the command's exit status and whatever it wrote to stderr.
	Run(cmd string, stdin io.Reader, stdout io.Writer) (exitCode int, stderr string, err error)
}

// FS is a container's filesystem, reached through a Runner.
//
// # On not requesting a PTY
//
// Every operation here moves bytes through a command's stdin or stdout. A PTY
// anywhere on that path is fatal to correctness, not merely untidy: the
// terminal line discipline rewrites "\n" as "\r\n" on output, so any file
// containing a 0x0a byte -- which is most of them -- arrives corrupted, and
// 0x03/0x04 are taken as signals rather than data.
//
// The console path deliberately DOES request a PTY, because `pct enter'
// misbehaves without one. Transfers therefore cannot share it, which is why
// this package has its own Runner rather than reusing the console's session.
type FS struct {
	Container Container
	Runner    Runner
}

// ErrNotRunningErr reports that the container is not running, which is a
// distinct condition from any filesystem error: nothing can be done about it
// by changing the path.
var ErrNotRunningErr = errors.New("container is not running")

// run executes a command and turns a non-zero exit into an error carrying
// what the command said.
//
// The container-not-running status is mapped to ErrNotRunningErr so callers
// can report it once, rather than every path looking like it does not exist.
func (f *FS) run(cmd string, stdin io.Reader, stdout io.Writer) error {
	code, stderr, err := f.Runner.Run(cmd, stdin, stdout)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case ErrNotRunning:
		return ErrNotRunningErr
	default:
		return commandError(code, stderr)
	}
}

// commandError turns a failed command into an error, mapping the messages
// coreutils and BusyBox produce onto the fs sentinels an SFTP server needs.
//
// The mapping matters because the SFTP protocol distinguishes "no such file"
// from "permission denied" from a generic failure, and a client shows the
// user a much better message when it gets the specific one. Matching on text
// is unattractive but it is the only signal a shell command gives: the exit
// status is 1 for every one of these.
func commandError(code int, stderr string) error {
	msg := strings.TrimSpace(stderr)
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "no such file"),
		strings.Contains(low, "not found"):
		return fmt.Errorf("%s: %w", msg, fs.ErrNotExist)
	case strings.Contains(low, "permission denied"):
		return fmt.Errorf("%s: %w", msg, fs.ErrPermission)
	case strings.Contains(low, "file exists"):
		return fmt.Errorf("%s: %w", msg, fs.ErrExist)
	case strings.Contains(low, "directory not empty"):
		return fmt.Errorf("%s: %w", msg, errNotEmpty)
	case strings.Contains(low, "is a directory"):
		return fmt.Errorf("%s: %w", msg, errIsDir)
	case msg == "":
		return fmt.Errorf("command failed with status %d", code)
	default:
		return errors.New(msg)
	}
}

var (
	errNotEmpty = errors.New("directory not empty")
	errIsDir    = errors.New("is a directory")
)

// Stat returns the attributes of one path.
func (f *FS) Stat(path string) (os.FileInfo, error) {
	var out strings.Builder
	if err := f.run(f.Container.StatCmd(path), nil, &out); err != nil {
		return nil, err
	}
	infos, err := parseStat(out.String())
	if err != nil {
		return nil, err
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("stat %s: %w", path, fs.ErrNotExist)
	}
	return infos[0], nil
}

// List returns the entries of a directory.
func (f *FS) List(dir string) ([]os.FileInfo, error) {
	var out strings.Builder
	if err := f.run(f.Container.ListCmd(dir), nil, &out); err != nil {
		return nil, err
	}
	return parseStat(out.String())
}

// ReadRangeTo streams length bytes of path from offset to w.
func (f *FS) ReadRangeTo(path string, offset, length int64, w io.Writer) error {
	return f.run(f.Container.ReadRangeCmd(path, offset, length), nil, w)
}

// WriteFrom replaces path with everything read from r.
func (f *FS) WriteFrom(path string, r io.Reader) error {
	return f.run(f.Container.WriteFileCmd(path), r, nil)
}

// WriteAtFrom writes everything read from r into path at offset, keeping the
// rest of the file.
func (f *FS) WriteAtFrom(path string, offset int64, r io.Reader) error {
	return f.run(f.Container.AppendFileCmd(path, offset), r, nil)
}

// Mkdir creates a directory.
func (f *FS) Mkdir(path string) error {
	return f.run(f.Container.Command("mkdir", path), nil, nil)
}

// Remove deletes a file.
func (f *FS) Remove(path string) error {
	// -f would hide a missing path, which the SFTP client should be told
	// about; -- stops a name beginning with "-" being read as a flag.
	return f.run(f.Container.Command("rm", "--", path), nil, nil)
}

// Rmdir removes an empty directory.
func (f *FS) Rmdir(path string) error {
	return f.run(f.Container.Command("rmdir", "--", path), nil, nil)
}

// Rename moves a path.
func (f *FS) Rename(from, to string) error {
	return f.run(f.Container.Command("mv", "--", from, to), nil, nil)
}

// Symlink creates a symbolic link at linkPath pointing at target.
func (f *FS) Symlink(target, linkPath string) error {
	return f.run(f.Container.Command("ln", "-s", "--", target, linkPath), nil, nil)
}

// Readlink returns a symlink's target.
func (f *FS) Readlink(path string) (string, error) {
	var out strings.Builder
	if err := f.run(f.Container.Command("readlink", "--", path), nil, &out); err != nil {
		return "", err
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

// Chmod sets a path's permission bits.
func (f *FS) Chmod(path string, mode os.FileMode) error {
	return f.run(f.Container.Command(
		"chmod", fmt.Sprintf("%04o", mode.Perm()), "--", path), nil, nil)
}

// Chown sets a path's owner. A negative id leaves that half unchanged.
func (f *FS) Chown(path string, uid, gid int) error {
	spec := ""
	switch {
	case uid >= 0 && gid >= 0:
		spec = fmt.Sprintf("%d:%d", uid, gid)
	case uid >= 0:
		spec = strconv.Itoa(uid)
	case gid >= 0:
		spec = ":" + strconv.Itoa(gid)
	default:
		return nil
	}
	return f.run(f.Container.Command("chown", spec, "--", path), nil, nil)
}

// Chtimes sets a path's access and modification times.
//
// `touch -d @<epoch>' is used because it is the one form both GNU coreutils
// and BusyBox accept for an absolute time; -t needs a formatted stamp whose
// century handling differs between them.
func (f *FS) Chtimes(path string, atime, mtime time.Time) error {
	if err := f.run(f.Container.Command(
		"touch", "-a", "-d", "@"+strconv.FormatInt(atime.Unix(), 10),
		"--", path), nil, nil); err != nil {
		return err
	}
	return f.run(f.Container.Command(
		"touch", "-m", "-d", "@"+strconv.FormatInt(mtime.Unix(), 10),
		"--", path), nil, nil)
}

// Truncate sets a file's length.
func (f *FS) Truncate(path string, size int64) error {
	// BusyBox truncate supports -s, as does coreutils.
	return f.run(f.Container.Command(
		"truncate", "-s", strconv.FormatInt(size, 10), "--", path), nil, nil)
}

// fileInfo is an os.FileInfo built from a stat line.
type fileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	uid     uint32
	gid     uint32
}

func (fi *fileInfo) Name() string       { return fi.name }
func (fi *fileInfo) Size() int64        { return fi.size }
func (fi *fileInfo) Mode() os.FileMode  { return fi.mode }
func (fi *fileInfo) ModTime() time.Time { return fi.modTime }
func (fi *fileInfo) IsDir() bool        { return fi.mode.IsDir() }

// Sys returns the owner, which an SFTP server needs to fill in the uid and
// gid of a reply.
func (fi *fileInfo) Sys() any {
	return &FileOwner{UID: fi.uid, GID: fi.gid}
}

// FileOwner carries a file's numeric owner through os.FileInfo.Sys.
type FileOwner struct {
	UID uint32
	GID uint32
}

// parseStat reads the output of StatCmd or ListCmd.
//
// The format is "<mode-hex> <size> <uid> <gid> <mtime> <name>", with the name
// last because it is the only field that may contain a space. Lines that do
// not parse are skipped rather than failing the whole listing: a directory
// containing one unreadable entry should still list.
func parseStat(out string) ([]os.FileInfo, error) {
	var infos []os.FileInfo
	sc := bufio.NewScanner(strings.NewReader(out))
	// A long listing can exceed the scanner's default line limit.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		fi, ok := parseStatLine(line)
		if !ok {
			continue
		}
		infos = append(infos, fi)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading stat output: %w", err)
	}
	return infos, nil
}

// parseStatLine parses one line, reporting whether it was well formed.
func parseStatLine(line string) (os.FileInfo, bool) {
	// SplitN with 6 keeps the name intact even when it contains spaces.
	parts := strings.SplitN(line, " ", 6)
	if len(parts) != 6 {
		return nil, false
	}
	rawMode, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return nil, false
	}
	size, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, false
	}
	uid, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return nil, false
	}
	gid, err := strconv.ParseUint(parts[3], 10, 32)
	if err != nil {
		return nil, false
	}
	mtime, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		return nil, false
	}
	// stat prints the path it was given; SFTP wants the base name.
	name := parts[5]
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return &fileInfo{
		name:    name,
		size:    size,
		mode:    modeFromStat(uint32(rawMode)),
		modTime: time.Unix(mtime, 0),
		uid:     uint32(uid),
		gid:     uint32(gid),
	}, true
}

// POSIX file type bits, as stat's %f reports them.
const (
	sIFMT   = 0o170000
	sIFSOCK = 0o140000
	sIFLNK  = 0o120000
	sIFREG  = 0o100000
	sIFBLK  = 0o060000
	sIFDIR  = 0o040000
	sIFCHR  = 0o020000
	sIFIFO  = 0o010000
)

// modeFromStat converts a raw POSIX mode into an os.FileMode.
//
// The type has to be translated rather than masked off, because os.FileMode
// encodes it in high bits of its own and an SFTP client decides whether to
// recurse based on it.
func modeFromStat(raw uint32) os.FileMode {
	mode := os.FileMode(raw & 0o777)
	switch raw & sIFMT {
	case sIFDIR:
		mode |= os.ModeDir
	case sIFLNK:
		mode |= os.ModeSymlink
	case sIFSOCK:
		mode |= os.ModeSocket
	case sIFIFO:
		mode |= os.ModeNamedPipe
	case sIFBLK:
		mode |= os.ModeDevice
	case sIFCHR:
		mode |= os.ModeDevice | os.ModeCharDevice
	case sIFREG:
		// The zero value already means a regular file.
	}
	// setuid, setgid and sticky, which a transfer with -p would preserve.
	if raw&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if raw&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if raw&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}
