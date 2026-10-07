// Command sftp-helper serves one directory over SFTP on stdin and stdout.
//
// It exists so that tests can drive the REAL scp and sftp clients against
// this package: both accept a program to speak the protocol to (scp -D,
// sftp -D), and expect it on stdin/stdout -- which is the same shape sshd
// gives `proxpass session' for a subsystem request.
//
// The directory stands in for a container's filesystem, and the commands run
// against it are the real generated ones with the nsenter wrapper stripped,
// so what the client exercises is the actual protocol handling and the actual
// shell commands.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"proxpass/internal/guestfs"
	"proxpass/internal/sftpserver"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sftp-helper <directory>")
		os.Exit(2)
	}
	root := os.Args[1]

	gfs := &guestfs.FS{
		Container: guestfs.Container{VMID: 101},
		Runner:    &localRunner{root: root},
	}
	if err := sftpserver.Serve(stdio{}, gfs); err != nil {
		fmt.Fprintf(os.Stderr, "sftp-helper: %v\n", err)
		os.Exit(1)
	}
}

// stdio is the transport, matching how sshd hands over a subsystem.
type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error                { return nil }

// localRunner runs the generated command against a directory on this machine.
//
// The nsenter wrapper is stripped and absolute paths are made relative to the
// served directory, which is what entering the container's mount namespace
// would otherwise achieve. Everything inside the wrapper -- the quoting, the
// stat format, the dd offsets -- runs exactly as it would on a node.
type localRunner struct{ root string }

func (r *localRunner) Run(cmd string, stdin io.Reader, stdout io.Writer) (exitCode int, stderrOut string, err error) {
	inner, ok := innerCommand(cmd)
	if !ok {
		return 0, "", errors.New("no command inside the nsenter wrapper")
	}
	script := "cd " + shQuote(r.root) + " && " + relativize(inner)

	var stderr bytes.Buffer
	c := exec.CommandContext(context.Background(), "sh", "-c", script)
	c.Stdin = stdin
	if stdout != nil {
		c.Stdout = stdout
	}
	c.Stderr = &stderr
	if runErr := c.Run(); runErr != nil {
		var ee interface{ ExitCode() int }
		if errors.As(runErr, &ee) {
			return ee.ExitCode(), stderr.String(), nil
		}
		return 0, stderr.String(), runErr
	}
	return 0, stderr.String(), nil
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// innerCommand extracts the argv the nsenter wrapper would have run.
func innerCommand(cmd string) (string, bool) {
	const marker = " -- "
	i := strings.Index(cmd, marker)
	if i < 0 {
		return "", false
	}
	rest := cmd[i+len(marker):]
	if j := strings.Index(rest, "; rc=$?"); j >= 0 {
		rest = rest[:j]
	}
	return rest, true
}

// relativize turns quoted absolute paths into relative ones, so that "/x"
// means the served directory's "x". Only the character after an opening quote
// is considered, so a slash inside a file name is left alone.
func relativize(cmd string) string {
	var b strings.Builder
	for i := 0; i < len(cmd); i++ {
		b.WriteByte(cmd[i])
		if cmd[i] != '\'' {
			continue
		}
		j := i + 1
		if j < len(cmd) && cmd[j] == '/' {
			if j+1 < len(cmd) && cmd[j+1] == '\'' {
				b.WriteByte('.')
			}
			j++
		}
		for ; j < len(cmd) && cmd[j] != '\''; j++ {
			b.WriteByte(cmd[j])
		}
		i = j - 1
	}
	return b.String()
}
