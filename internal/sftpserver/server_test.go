package sftpserver_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"

	"proxpass/internal/sftpserver"
)

// newFS returns an FS backed by a temporary directory, served by the REAL
// guest helper running as a local process.
//
// Only the namespace entry is missing -- that is nsenter's job and is covered
// against a real node. Everything a client touches here is the production
// path: the protocol framing, the attribute translation and the helper's own
// file operations.
func newFS(t *testing.T) (gfs sftpserver.FS, root string) {
	t.Helper()
	root = t.TempDir()
	return newHelperFS(t, root), root
}

// newClient starts the server on an in-memory pipe and returns a real SFTP
// client speaking to it.
//
// A real client is used rather than hand-written packets so that the test
// fails if the protocol is wrong, not merely if our own idea of it changes.
func newClient(t *testing.T, gfs sftpserver.FS) *sftp.Client {
	t.Helper()
	srvIn, cliOut := io.Pipe()
	cliIn, srvOut := io.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- sftpserver.Serve(rwc{Reader: srvIn, Writer: srvOut}, gfs)
	}()

	client, err := sftp.NewClientPipe(cliIn, cliOut)
	if err != nil {
		t.Fatalf("sftp client: %v", err)
	}
	t.Cleanup(func() {
		// Order matters. Closing the client's OUTBOUND pipe first gives the
		// server EOF, which ends Serve and lets it close its own side;
		// client.Close() then returns instead of waiting for a reply that
		// can never come. Calling client.Close() first deadlocks: it waits
		// on a response from a server that is still blocked reading.
		_ = cliOut.Close()
		<-done
		_ = srvOut.Close()
		_ = client.Close()
	})
	return client
}

type rwc struct {
	io.Reader
	io.Writer
}

func (rwc) Close() error { return nil }

// TestUploadIsBinaryExact is the property the whole design turns on: a file
// must arrive byte for byte.
//
// Random content is used rather than text because the failure this guards
// against is newline translation, which text would hide and which a PTY
// anywhere on the path would cause.
func TestUploadIsBinaryExact(t *testing.T) {
	gfs, root := newFS(t)
	client := newClient(t, gfs)

	payload := make([]byte, 300*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	f, err := client.Create("/upload.bin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "upload.bin"))
	if err != nil {
		t.Fatalf("reading what landed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("upload was not byte exact: got %d bytes, want %d",
			len(got), len(payload))
	}
}

// TestDownloadIsBinaryExact is the same property in the other direction.
func TestDownloadIsBinaryExact(t *testing.T) {
	gfs, root := newFS(t)
	client := newClient(t, gfs)

	payload := make([]byte, 300*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "download.bin"), payload, 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	f, err := client.Open("/download.bin")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("download was not byte exact: got %d bytes, want %d",
			len(got), len(payload))
	}
}

// TestUploadWithNewlinesSurvives targets the specific corruption a PTY on the
// transfer path causes: "\n" rewritten as "\r\n". A payload that is all
// newlines would double in size.
func TestUploadWithNewlinesSurvives(t *testing.T) {
	gfs, root := newFS(t)
	client := newClient(t, gfs)

	payload := bytes.Repeat([]byte{'\n'}, 4096)
	f, err := client.Create("/newlines.bin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "newlines.bin"))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("newlines were translated: got %d bytes, want %d",
			len(got), len(payload))
	}
}

// TestListReportsNamesTypesAndSizes covers the listing an sftp client shows
// and an scp -r needs.
func TestListReportsNamesTypesAndSizes(t *testing.T) {
	gfs, root := newFS(t)
	client := newClient(t, gfs)

	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	// A dotfile, which the glob has to include.
	if err := os.WriteFile(filepath.Join(root, ".hidden"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	byName := map[string]os.FileInfo{}
	for _, e := range entries {
		byName[e.Name()] = e
	}

	a, ok := byName["a.txt"]
	if !ok {
		t.Fatalf("a.txt missing from the listing: %v", names(entries))
	}
	if a.Size() != 5 {
		t.Errorf("a.txt size = %d, want 5", a.Size())
	}
	if a.IsDir() {
		t.Error("a.txt reported as a directory")
	}

	sub, ok := byName["sub"]
	if !ok {
		t.Fatalf("sub missing from the listing: %v", names(entries))
	}
	if !sub.IsDir() {
		t.Error("sub not reported as a directory")
	}

	if _, ok := byName[".hidden"]; !ok {
		t.Errorf("a dotfile was not listed: %v", names(entries))
	}
	// "." and ".." must not appear: clients add them and some are confused
	// by duplicates.
	for _, bad := range []string{".", ".."} {
		if _, ok := byName[bad]; ok {
			t.Errorf("%q must not be listed", bad)
		}
	}
}

// TestStatOnAMissingFileSaysSoSpecifically checks the error mapping. Without
// it every failure becomes "failure" and a client cannot tell the user what
// went wrong.
func TestStatOnAMissingFileSaysSoSpecifically(t *testing.T) {
	gfs, _ := newFS(t)
	client := newClient(t, gfs)

	_, err := client.Stat("/does-not-exist")
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected a not-exist error, got %v", err)
	}
}

// TestAFileNameWithShellMetacharactersIsData is the injection test at the
// protocol level: a name full of shell syntax must create a file with that
// name, not run anything.
func TestAFileNameWithShellMetacharactersIsData(t *testing.T) {
	gfs, root := newFS(t)
	client := newClient(t, gfs)

	const hostile = `we'ird $(touch pwned) ;name.txt`
	f, err := client.Create("/" + hostile)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write([]byte("data")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "pwned")); err == nil {
		t.Fatal("the command substitution in the file name EXECUTED")
	}
	got, err := os.ReadFile(filepath.Join(root, hostile))
	if err != nil {
		t.Fatalf("the hostile name did not become a file: %v", err)
	}
	if string(got) != "data" {
		t.Fatalf("content = %q, want %q", got, "data")
	}
}

// TestMkdirAndRemove covers the operations an scp -r upload performs.
func TestMkdirAndRemove(t *testing.T) {
	gfs, root := newFS(t)
	client := newClient(t, gfs)

	if err := client.Mkdir("/newdir"); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	fi, err := os.Stat(filepath.Join(root, "newdir"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("mkdir did not create a directory: %v", err)
	}

	if err := client.RemoveDirectory("/newdir"); err != nil {
		t.Fatalf("rmdir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "newdir")); !os.IsNotExist(err) {
		t.Fatalf("rmdir did not remove the directory: %v", err)
	}
}

// TestRename covers the atomic-replace an sftp client uses to finish an
// upload safely.
func TestRename(t *testing.T) {
	gfs, root := newFS(t)
	client := newClient(t, gfs)

	if err := os.WriteFile(filepath.Join(root, "from.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if err := client.Rename("/from.txt", "/to.txt"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "to.txt")); err != nil {
		t.Fatalf("rename did not move the file: %v", err)
	}
}

// TestChmodIsApplied covers what scp does when preserving a mode.
func TestChmodIsApplied(t *testing.T) {
	gfs, root := newFS(t)
	client := newClient(t, gfs)

	path := filepath.Join(root, "exec.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if err := client.Chmod("/exec.sh", 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o755 {
		t.Fatalf("mode = %04o, want 0755", got)
	}
}

// TestWriteAtAnOffsetKeepsEarlierBytes covers a client that writes a file in
// several chunks, which is every client for a file of any size. Without
// conv=notrunc each chunk would discard the last.
func TestWriteAtAnOffsetKeepsEarlierBytes(t *testing.T) {
	gfs, root := newFS(t)
	client := newClient(t, gfs)

	f, err := client.Create("/chunked.bin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write([]byte("AAAA")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	// WriteAt past the first chunk, as a client filling a later region does.
	if _, err := f.WriteAt([]byte("BBBB"), 4); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "chunked.bin"))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(got) != "AAAABBBB" {
		t.Fatalf("chunked write lost data: got %q want %q", got, "AAAABBBB")
	}
}

// names is a helper for failure messages.
func names(infos []os.FileInfo) []string {
	out := make([]string, 0, len(infos))
	for _, fi := range infos {
		out = append(out, fi.Name())
	}
	return out
}
