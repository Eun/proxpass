package guesthelper_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxpass/internal/guesthelper"
)

// pipePair wires a client and a server together in memory, the way the SSH
// session wires them over the wire.
type pipePair struct {
	io.Reader
	io.Writer
}

// startHelper runs the real helper binary against root and returns a client
// talking to it.
//
// The binary is built once per test run and driven over real pipes, so this
// exercises the framing, the payload handling and the helper's own file
// operations -- not a reimplementation of them.
func startHelper(t *testing.T, root string) *guesthelper.Client {
	t.Helper()
	bin := buildHelper(t)

	cmd := helperCommand(t, bin, root)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	client, err := guesthelper.NewClient(pipePair{Reader: stdout, Writer: stdin}, 60*time.Second)
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

func TestStatAndList(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a.txt"), "hello")
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := startHelper(t, root)

	fi, err := c.Stat(filepath.Join(root, "a.txt"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != 5 {
		t.Errorf("size = %d, want 5", fi.Size())
	}
	if fi.IsDir() {
		t.Error("a.txt reported as a directory")
	}

	entries, err := c.List(root)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	var sawDir bool
	for _, e := range entries {
		if e.Name() == "sub" && e.IsDir() {
			sawDir = true
		}
	}
	if !sawDir {
		t.Error("the subdirectory was not reported as one")
	}
}

// TestMissingFileIsNotExist is the test that matters for the SFTP layer: the
// sentinel has to survive the wire, or a client is told "failure" instead of
// "No such file".
func TestMissingFileIsNotExist(t *testing.T) {
	c := startHelper(t, t.TempDir())
	_, err := c.Stat("/definitely/not/here")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
}

// TestLargeRoundTrip pushes a payload well past one chunk, which is what
// catches an offset bug in the chunking.
func TestLargeRoundTrip(t *testing.T) {
	root := t.TempDir()
	c := startHelper(t, root)

	// Deliberately not a multiple of the chunk size, so the final short
	// write is exercised.
	payload := bytes.Repeat([]byte("0123456789abcdef"), 70000) // ~1.1 MiB
	path := filepath.Join(root, "big.bin")

	if err := c.WriteFrom(path, bytes.NewReader(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var got bytes.Buffer
	if err := c.ReadRangeTo(path, 0, -1, &got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if sha256.Sum256(got.Bytes()) != sha256.Sum256(payload) {
		t.Fatalf("round trip corrupted: got %d bytes, want %d", got.Len(), len(payload))
	}
}

// TestWriteAtOffsets writes chunks out of order, which is what an SFTP client
// does and what a naive truncate-per-write would destroy.
func TestWriteAtOffsets(t *testing.T) {
	root := t.TempDir()
	c := startHelper(t, root)
	path := filepath.Join(root, "sparse.bin")

	if err := c.WriteAtFrom(path, 10, strings.NewReader("SECOND")); err != nil {
		t.Fatalf("write at 10: %v", err)
	}
	if err := c.WriteAtFrom(path, 0, strings.NewReader("FIRST")); err != nil {
		t.Fatalf("write at 0: %v", err)
	}
	var got bytes.Buffer
	if err := c.ReadRangeTo(path, 0, -1, &got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(got.String(), "FIRST") || !strings.Contains(got.String(), "SECOND") {
		t.Fatalf("out-of-order writes lost data: %q", got.String())
	}
}

func TestRangedRead(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "r.txt")
	write(t, path, "0123456789")
	c := startHelper(t, root)

	var got bytes.Buffer
	if err := c.ReadRangeTo(path, 3, 4, &got); err != nil {
		t.Fatalf("ranged read: %v", err)
	}
	if got.String() != "3456" {
		t.Fatalf("got %q, want %q", got.String(), "3456")
	}
}

func TestFileOps(t *testing.T) {
	root := t.TempDir()
	c := startHelper(t, root)

	dir := filepath.Join(root, "d")
	if err := c.Mkdir(dir); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src := filepath.Join(dir, "one.txt")
	if err := c.WriteFrom(src, strings.NewReader("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	dst := filepath.Join(dir, "two.txt")
	if err := c.Rename(src, dst); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := c.Chmod(dst, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	fi, err := c.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}

	link := filepath.Join(dir, "link")
	if err := c.Symlink(dst, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	target, err := c.Readlink(link)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != dst {
		t.Errorf("readlink = %q, want %q", target, dst)
	}

	if err := c.Remove(link); err != nil {
		t.Fatalf("remove link: %v", err)
	}
	if err := c.Remove(dst); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	if err := c.Rmdir(dir); err != nil {
		t.Fatalf("rmdir: %v", err)
	}
	if _, err := c.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("directory survived rmdir: %v", err)
	}
}

// TestRmdirRefusesNonEmpty pins the semantic SFTP expects: Rmdir is not a
// recursive delete.
func TestRmdirRefusesNonEmpty(t *testing.T) {
	root := t.TempDir()
	c := startHelper(t, root)
	dir := filepath.Join(root, "full")
	if err := c.Mkdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteFrom(filepath.Join(dir, "f"), strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if err := c.Rmdir(dir); err == nil {
		t.Fatal("rmdir removed a non-empty directory")
	}
}

func TestChtimes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "t.txt")
	write(t, path, "x")
	c := startHelper(t, root)

	want := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := c.Chtimes(path, want, want); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	fi, err := c.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(want) {
		t.Errorf("mtime = %v, want %v", fi.ModTime(), want)
	}
}

func TestTruncate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "t.bin")
	write(t, path, "0123456789")
	c := startHelper(t, root)

	if err := c.Truncate(path, 4); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	fi, err := c.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 4 {
		t.Errorf("size = %d, want 4", fi.Size())
	}
}

// TestWriteFromTruncates pins that replacing a file's contents with something
// SHORTER does not leave the old tail behind.
func TestWriteFromTruncates(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "w.txt")
	write(t, path, "aaaaaaaaaaaaaaaaaaaa")
	c := startHelper(t, root)

	if err := c.WriteFrom(path, strings.NewReader("bb")); err != nil {
		t.Fatalf("write: %v", err)
	}
	var got bytes.Buffer
	if err := c.ReadRangeTo(path, 0, -1, &got); err != nil {
		t.Fatal(err)
	}
	if got.String() != "bb" {
		t.Fatalf("got %q, want %q -- the old contents were not truncated", got.String(), "bb")
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestWriteFromCreatesAnEmptyFile pins the client half of issue #104.
//
// Streaming an empty reader sends no write at all, so the obvious
// "truncate then stream" shape leaves a missing path missing. The write that
// opens a file must be unconditional.
func TestWriteFromCreatesAnEmptyFile(t *testing.T) {
	root := t.TempDir()
	c := startHelper(t, root)
	path := filepath.Join(root, "empty.bin")

	if err := c.WriteFrom(path, strings.NewReader("")); err != nil {
		t.Fatalf("write: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("an empty file was not created: %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("size = %d, want 0", fi.Size())
	}
}

// TestWriteFromTruncatesViaTheOpeningWrite pins that the truncation rides on
// the first write rather than a separate call, and that later chunks do NOT
// truncate -- otherwise each would discard its predecessor.
func TestWriteFromTruncatesViaTheOpeningWrite(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "t.bin")
	// Longer than one chunk, so the multi-chunk path is exercised.
	write(t, path, strings.Repeat("x", 5))
	c := startHelper(t, root)

	payload := strings.Repeat("ab", 300000) // ~586 KiB, several chunks
	if err := c.WriteFrom(path, strings.NewReader(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("got %d bytes, want %d -- a later chunk truncated the file",
			len(got), len(payload))
	}
}
