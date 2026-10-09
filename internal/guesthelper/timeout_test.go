package guesthelper_test

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"proxpass/internal/guesthelper"
)

// TestIdleTimeoutExits is the point of the timeout: a helper whose peer
// vanished without closing anything must not stay on the Proxmox node.
//
// The timeout is negotiated at handshake, so the test can ask for a short one
// rather than waiting out the sixty-second default.
func TestIdleTimeoutExits(t *testing.T) {
	bin := buildHelper(t)
	cmd := exec.CommandContext(t.Context(), bin, "serve")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Negotiate a one-second idle timeout, then go quiet WITHOUT closing
	// stdin -- which is exactly what a dropped connection looks like.
	if _, err := guesthelper.NewClient(pipePair{Reader: stdout, Writer: stdin}, time.Second); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("helper exited with an error: %v (stderr: %s)", err, stderr.String())
		}
		if !strings.Contains(stderr.String(), "idle") {
			t.Errorf("stderr did not explain the exit: %q", stderr.String())
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("helper did not exit after going idle -- it would leak on the node")
	}
	_ = stdin.Close()
}

// TestActivityDefersTimeout pins the other half: a transfer that keeps
// working must not be cut off by the timeout.
func TestActivityDefersTimeout(t *testing.T) {
	bin := buildHelper(t)
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
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})

	client, err := guesthelper.NewClient(pipePair{Reader: stdout, Writer: stdin}, time.Second)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Keep going for comfortably longer than the timeout, touching the
	// helper every half second. If the timer were not reset per request,
	// one of these would fail.
	root := t.TempDir()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.Stat(root); err != nil {
			t.Fatalf("helper died mid-transfer: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestStdinCloseExits pins the ordinary teardown: closing stdin ends the
// helper at once, without waiting for the idle timer.
func TestStdinCloseExits(t *testing.T) {
	bin := buildHelper(t)
	cmd := exec.CommandContext(t.Context(), bin, "serve")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := guesthelper.NewClient(pipePair{Reader: stdout, Writer: stdin}, time.Minute); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	start := time.Now()
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if err != nil && !errors.As(err, &exitErr) {
			t.Fatalf("wait: %v", err)
		}
		// A minute-long idle timeout was negotiated, so anything near
		// that would mean EOF was not what ended it.
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("exit took %v: stdin close did not end the session", elapsed)
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("helper ignored EOF on stdin")
	}
}
