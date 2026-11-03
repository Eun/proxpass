package models_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxpass/internal/models"
)

// entrypointPath is the container entrypoint that generates the Proxmox key.
const entrypointPath = "../../docker/entrypoint.sh"

// TestEntrypointDefaultsToTheSSHKeyPath keeps the shell and the Go constant
// in agreement.
//
// The entrypoint writes the key and `proxpass serve' reads it, so a change to
// either path alone leaves the ssh connection type looking for a file nothing
// creates -- and the failure would surface as "no ssh key" on a deployment
// that plainly has one.
func TestEntrypointDefaultsToTheSSHKeyPath(t *testing.T) {
	b, err := os.ReadFile(filepath.Clean(entrypointPath))
	if err != nil {
		t.Fatalf("reading the entrypoint: %v", err)
	}
	script := string(b)

	// The entrypoint builds the path from PROXPASS_HOST_KEY_DIR, so compare
	// against the expansion rather than the literal.
	const keyDirVar = "PROXPASS_HOST_KEY_DIR=\""
	i := strings.Index(script, keyDirVar)
	if i < 0 {
		t.Fatal("the entrypoint no longer sets PROXPASS_HOST_KEY_DIR")
	}
	rest := script[i+len(keyDirVar):]
	end := strings.Index(rest, "\"")
	if end < 0 {
		t.Fatal("PROXPASS_HOST_KEY_DIR is not a closed string literal")
	}
	keyDir := rest[:end]

	want := keyDir + "/proxpass_key"
	if models.DefaultSSHKeyPath != want {
		t.Fatalf("models.DefaultSSHKeyPath is %q but the entrypoint writes %q",
			models.DefaultSSHKeyPath, want)
	}

	// And the variable it exports has to be the one Go reads.
	if !strings.Contains(script, "export "+models.SSHKeyPathEnv) {
		t.Fatalf("the entrypoint does not export %s", models.SSHKeyPathEnv)
	}
}

// TestEntrypointDoesNotExportThePrivateKeyItself guards the reason the key is
// passed by path.
//
// An environment variable holding the key would be readable through
// /proc/<pid>/environ by anything running as the same user, which is every
// alias session. The file is root-only instead.
func TestEntrypointDoesNotExportThePrivateKeyItself(t *testing.T) {
	b, err := os.ReadFile(filepath.Clean(entrypointPath))
	if err != nil {
		t.Fatalf("reading the entrypoint: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		// PROXPASS_SSH_KEY_FILE is the path and is expected; a bare
		// PROXPASS_SSH_KEY would be the key material.
		if strings.Contains(line, "export PROXPASS_SSH_KEY") &&
			!strings.Contains(line, models.SSHKeyPathEnv) {
			t.Fatalf("the entrypoint exports the key material itself: %q", line)
		}
	}
}

// TestEntrypointLetsServeWriteTheNSSConfig guards the fix for the lock-out bug.
//
// The NSS token and the nss_http.json it is injected into used to be two sides
// that could drift: the entrypoint sed'd a generated token into a checked-in
// file, and a container recreate reset that file to its placeholder. If serve
// and the file ever disagreed, every NSS lookup was a 401 and nobody could log
// in. serve now WRITES the config itself from its own token (one writer, no
// drift), so the entrypoint must point serve at the path (PROXPASS_NSS_CONFIG)
// and must NOT sed a token into the file any more.
func TestEntrypointLetsServeWriteTheNSSConfig(t *testing.T) {
	b, err := os.ReadFile(filepath.Clean(entrypointPath))
	if err != nil {
		t.Fatalf("reading the entrypoint: %v", err)
	}
	script := string(b)

	// serve is told where to render the config.
	if !strings.Contains(script, "export PROXPASS_NSS_CONFIG") {
		t.Fatal("the entrypoint does not export PROXPASS_NSS_CONFIG; serve would not know where to write nss_http.json")
	}
	// The old drift-prone templating is gone: no sed of the token placeholder.
	if strings.Contains(script, "__PROXPASS_NSS_TOKEN__") {
		t.Fatal("the entrypoint still templates the NSS token into nss_http.json; " +
			"serve writes it now, and the shell copy can drift and lock everyone out")
	}
}
