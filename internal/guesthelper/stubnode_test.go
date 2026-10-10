package guesthelper_test

import (
	"os"
	"path/filepath"
	"testing"
)

// stubNode builds a directory of fake node programs and returns it, for
// prepending to PATH.
//
// The generated command lines are shell, and the only way to test shell
// faithfully is to let a shell parse it. These stubs stand in for the two
// programs it calls so that parsing, quoting and expansion happen exactly
// where they would on a real node, without needing one.
//
// enterBody is spliced into the nsenter stub after its own flags have been
// consumed, with the shell path already shifted off, so "$1" is the first
// argument the container would receive.
func stubNode(t *testing.T, enterBody string) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		// 0o755 because these are executed by PATH lookup; they are
		// throwaway scripts under t.TempDir() and hold nothing secret.
		//nolint:gosec // G306: a stub program has to be executable.
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// The command asks the node for the container's pid before entering.
	write(lxcInfoProgram, "#!/bin/sh\necho 'PID:      1234'\n")

	// Consume nsenter's own flags, then the shell path, then run the body.
	write(nsenterProgram, `#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    --) shift; break ;;
    -t|-S|-G) shift 2 ;;
    *) shift ;;
  esac
done
shift
`+enterBody)

	return bin
}

// The node programs the generated commands invoke.
const (
	nsenterProgram = "nsenter"
	lxcInfoProgram = "lxc-info"
)
