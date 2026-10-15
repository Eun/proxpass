package session_test

import (
	"log"
	"strings"
	"testing"

	"proxpass/internal/models"
	"proxpass/internal/session"
	"proxpass/internal/testenv"
)

const (
	// helpFlag is the request that reaches the help branch.
	helpFlag = "--help"
	// cmdUptime is an ordinary command, used where the content does
	// not matter.
	cmdUptime = "uptime"
)

// Every session says which branch it took, before it takes it.
//
// A file transfer used to announce nothing at all, so a failing scp left
// no trace: there was no way to tell "not recognized as sftp" from
// "recognized, then failed". The client cannot tell either, because sshd
// discards a subsystem session's stderr and shows only "Connection
// closed".
func TestEverySessionLogsItsDispatch(t *testing.T) {
	for _, tc := range []struct {
		name, command, wantKind string
	}{
		{"interactive", "", "kind=login-name"},
		{"command", cmdUptime, "kind=command"},
		{"sftp full path", "/usr/lib/openssh/sftp-server", "kind=sftp"},
		{"sftp internal", "internal-sftp", "kind=sftp"},
		{"help", helpFlag, "kind=help"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo(t)
			seedGuest(t, repo)

			var logbuf strings.Builder
			tb := newTerminal("q\n")
			d := newDeps(repo, tb, &testenv.MockProxier{})
			d.Logger = log.New(&logbuf, "", 0)
			d.LoginName = userAlice
			d.IdentityName = userAlice
			d.IsAdmin = true
			d.Debug = true
			d.Command = tc.command

			session.Run(t.Context(), d)

			got := logbuf.String()
			if !strings.Contains(got, tc.wantKind) {
				t.Errorf("log does not say %q:\n%s", tc.wantKind, got)
			}
			if !strings.Contains(got, "session:") {
				t.Errorf("no dispatch line at all:\n%s", got)
			}
		})
	}
}

// The logged command is quoted and bounded.
//
// It comes from the client, so an embedded newline must not let it forge
// a second log line, and a very long one must not flood the file.
func TestTheLoggedCommandCannotForgeALine(t *testing.T) {
	repo := newRepo(t)
	seedGuest(t, repo)

	var logbuf strings.Builder
	tb := newTerminal("")
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.Logger = log.New(&logbuf, "", 0)
	d.LoginName = userAlice
	d.IdentityName = userAlice
	d.IsAdmin = true
	d.Debug = true
	d.Command = "x\nproxpass: FORGED ADMIN LINE"

	session.Run(t.Context(), d)

	// The payload may appear -- quoted, as inert text. What must NOT
	// happen is it becoming a line of its OWN, which is what an
	// unescaped newline would do.
	out := logbuf.String()
	if !strings.Contains(out, `\n`) {
		t.Errorf("the newline was not escaped: %q", out)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.HasPrefix(line, "proxpass: FORGED") {
			t.Errorf("the client forged a log line of its own: %q", line)
		}
	}
	// One dispatch line, not two.
	if n := strings.Count(out, "session: kind="); n != 1 {
		t.Errorf("got %d dispatch lines, want 1:\n%s", n, out)
	}
}

func TestALongCommandIsTruncatedInTheLog(t *testing.T) {
	repo := newRepo(t)
	seedGuest(t, repo)

	var logbuf strings.Builder
	tb := newTerminal("")
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.Logger = log.New(&logbuf, "", 0)
	d.LoginName = userAlice
	d.IdentityName = userAlice
	d.IsAdmin = true
	d.Debug = true
	d.Command = strings.Repeat("A", 5000)

	session.Run(t.Context(), d)

	if !strings.Contains(logbuf.String(), "truncated") {
		t.Error("a 5000-character command was not truncated in the log")
	}
	if len(logbuf.String()) > 1000 {
		t.Errorf("the dispatch line is %d bytes; it should be bounded",
			len(logbuf.String()))
	}
}

// A node transfer logs its dispatch as sftp too, not as a command.
func TestANodeTransferLogsAsSFTP(t *testing.T) {
	repo := newRepo(t)
	inst := seedNodeInstance(t, repo, instRome)
	client := grantNode(t, repo, inst.ID)

	var logbuf strings.Builder
	tb := newTerminal("")
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.Logger = log.New(&logbuf, "", 0)
	d.LoginName = instRome
	d.IdentityName = userAlice
	d.ClientID = client.ID
	d.Debug = true
	d.Command = "/usr/lib/openssh/sftp-server"

	session.Run(t.Context(), d)

	got := logbuf.String()
	if !strings.Contains(got, "kind=sftp") {
		t.Errorf("a node transfer did not log as sftp:\n%s", got)
	}
	// The IDENTITY, never the caller-chosen login name.
	if !strings.Contains(got, userAlice+": session:") {
		t.Errorf("the dispatch line does not name the identity:\n%s", got)
	}
	if strings.Contains(got, `login=`) {
		t.Errorf("the dispatch line records the caller-chosen login name, "+
			"which lets one caller forge another's entries:\n%s", got)
	}
}

// Guard: the model fixture must stay referenced so the import is real.
var _ = models.GuestTypeCT

// The diagnostics are OFF unless asked for.
//
// They are verbose and one of them names the client's command, which
// belongs in an operator's log only when an operator turned it on.
func TestDispatchIsNotLoggedByDefault(t *testing.T) {
	repo := newRepo(t)
	seedGuest(t, repo)

	var logbuf strings.Builder
	tb := newTerminal("")
	d := newDeps(repo, tb, &testenv.MockProxier{})
	d.Logger = log.New(&logbuf, "", 0)
	d.LoginName = userAlice
	d.IdentityName = userAlice
	d.IsAdmin = true
	d.Command = cmdUptime
	// d.Debug deliberately left false.

	session.Run(t.Context(), d)

	if strings.Contains(logbuf.String(), "session: kind=") {
		t.Errorf("the dispatch line was logged without --log-level=debug:\n%s",
			logbuf.String())
	}
}
