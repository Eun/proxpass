package console_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxpass/internal/console"
)

// sshdConfigPath is the drop-in the image installs as
// /etc/ssh/sshd_config.d/proxpass.conf.
const sshdConfigPath = "../../docker/sshd_config.d/proxpass.conf"

// acceptedEnv returns the variable names listed in the drop-in's AcceptEnv
// directives.
func acceptedEnv(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(sshdConfigPath))
	if err != nil {
		t.Fatalf("reading the sshd drop-in: %v", err)
	}
	var names []string
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !strings.EqualFold(fields[0], "AcceptEnv") {
			continue
		}
		names = append(names, fields[1:]...)
	}
	return names
}

// The status bar escape hatch has to survive the trip from the client to the
// session process, and sshd is what decides whether it does.
//
// barDisabled reads the variable with os.Getenv, but a session's environment
// is built by sshd: it does not inherit the container's, and it discards any
// variable the client sends that AcceptEnv does not name. The unit test for
// barDisabled passes either way because t.Setenv sets the variable directly,
// so nothing in the suite noticed when the old allowlist was dropped in
// 755aee5 and the documented PROXPASS_DISABLE_STATUSBAR=1 became a no-op in
// the shipped image. Verified against a running container: with this line
// absent the variable is missing from the session environment entirely.
func TestSSHDConfigAcceptsTheStatusBarEnv(t *testing.T) {
	for _, name := range acceptedEnv(t) {
		if name == console.DisableStatusBarEnv {
			return
		}
	}
	t.Errorf("the sshd drop-in has no AcceptEnv for %s, so a client cannot "+
		"turn the status bar off; AcceptEnv names are %q",
		console.DisableStatusBarEnv, acceptedEnv(t))
}

// AcceptEnv must name the variable exactly and never match a pattern.
//
// The session binary takes --admin-key from PROXPASS_ADMIN_KEY and --data
// from PROXPASS_DATA, so a client that can set those chooses which database
// its own session opens and which keys it is checked against. Confirmed by
// probing a container with "AcceptEnv PROXPASS_*" added: a client-supplied
// PROXPASS_DATA made the session create and use a database of the client's
// choosing. A wildcard here would therefore be an escalation, not a
// convenience, which is why this asserts on the shape of the directive and
// not merely that the status bar variable is covered.
func TestSSHDConfigDoesNotAcceptEnvPatterns(t *testing.T) {
	for _, name := range acceptedEnv(t) {
		if !strings.HasPrefix(name, "PROXPASS_") {
			// LANG and LC_* come from the Debian default and are inert.
			continue
		}
		if strings.ContainsAny(name, "*?") {
			t.Errorf("AcceptEnv %q is a pattern: it would also pass "+
				"PROXPASS_ADMIN_KEY and PROXPASS_DATA to the session, "+
				"letting a client choose its own admin keys and database",
				name)
		}
	}
}
