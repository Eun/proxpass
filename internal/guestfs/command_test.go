package guestfs

import (
	"os/exec"
	"strings"
	"testing"
)

// TestShellQuoteSurvivesAShell runs each quoted string through a real shell
// and checks it comes back byte-identical.
//
// This is the boundary that keeps a client-chosen path from becoming code, so
// it is tested against sh rather than against an idea of what sh does.
func TestShellQuoteSurvivesAShell(t *testing.T) {
	requireShell(t)
	hostile := []string{
		"plain.txt",
		"with space.txt",
		"it's.txt",
		`quote"double`,
		"semi;colon",
		"pipe|char",
		"dollar$HOME",
		"back`tick`",
		"amp&sand",
		"redirect>out",
		"glob*?[]",
		"newline\nsecond",
		"back\\slash",
		"paren(s)",
		"dash-leading",
		"--looks-like-a-flag",
		"$(echo pwned)",
		"'; echo pwned; '",
		"nul-free \x01\x02",
		"ünïcøde",
	}
	for _, s := range hostile {
		// printf %s rather than echo: echo mangles backslashes.
		//nolint:gosec // feeding hostile input to a shell IS the test.
		out, err := exec.CommandContext(t.Context(), "sh", "-c", "printf %s "+shellQuote(s)).Output()
		if err != nil {
			t.Fatalf("shell rejected %q: %v", s, err)
		}
		if string(out) != s {
			t.Errorf("round trip changed the value:\n  in:  %q\n  out: %q", s, string(out))
		}
	}
}

// TestShellQuoteAllKeepsArgumentsSeparate checks that a path containing a
// space stays ONE argument, which is what stops a crafted name from adding
// another.
func TestShellQuoteAllKeepsArgumentsSeparate(t *testing.T) {
	requireShell(t)
	// Three arguments, two of which would split on whitespace unquoted.
	cmd := "printf '[%s]' " + shellQuoteAll("a b", "c;d", "e")
	out, err := exec.CommandContext(t.Context(), "sh", "-c", cmd).Output()
	if err != nil {
		t.Fatalf("sh: %v", err)
	}
	const want = "[a b][c;d][e]"
	if string(out) != want {
		t.Fatalf("argument boundaries not preserved: got %q want %q", out, want)
	}
}

// TestCommandEntersTheMountAndRootNamespace pins the flags that make this
// safe. -r is as important as -m: without it nsenter keeps the NODE's root
// and a container-absolute path silently reads the node's file instead.
func TestCommandEntersTheMountAndRootNamespace(t *testing.T) {
	got := Container{VMID: 101}.Command("true")
	for _, want := range []string{"nsenter", "-m", "-r", "-w"} {
		if !strings.Contains(got, want) {
			t.Errorf("command is missing %q:\n%s", want, got)
		}
	}
	// -r and -w must be BARE. A separated argument is read as the program
	// to execute, because their arguments are optional.
	if strings.Contains(got, "-w /") || strings.Contains(got, "-r /") {
		t.Errorf("-r/-w must not take a separated argument:\n%s", got)
	}
}

// TestCommandEntersTheUserNamespaceOnlyWhenUnprivileged covers both
// directions, because getting it wrong breaks a container either way: without
// -U an unprivileged container's files land owned by nobody, and WITH it a
// privileged container's nsenter fails with EINVAL because the caller is
// already a member of that namespace.
func TestCommandEntersTheUserNamespaceOnlyWhenUnprivileged(t *testing.T) {
	unpriv := Container{VMID: 101, Unprivileged: true}.Command("true")
	if !strings.Contains(unpriv, "-U") || !strings.Contains(unpriv, "-S 0") {
		t.Errorf("an unprivileged container must enter the user namespace as root:\n%s", unpriv)
	}

	priv := Container{VMID: 101}.Command("true")
	if strings.Contains(priv, "-U") {
		t.Errorf("a privileged container must NOT enter the user namespace:\n%s", priv)
	}
}

// TestCommandVerifiesThePidTwice pins the pid-reuse guard: the pid is read,
// used and re-read inside one command, because between two SSH round trips
// the container could restart and the pid be reused by an unrelated process.
func TestCommandVerifiesThePidTwice(t *testing.T) {
	got := Container{VMID: 101}.Command("true")
	if n := strings.Count(got, "lxc-info"); n != 2 {
		t.Fatalf("expected the pid to be resolved twice, found %d:\n%s", n, got)
	}
	if !strings.Contains(got, `[ "$pid" = "$pid2" ]`) {
		t.Fatalf("expected the two pids to be compared:\n%s", got)
	}
}

// TestCommandIsValidShell checks every generated command parses, which a
// quoting mistake would break.
func TestCommandIsValidShell(t *testing.T) {
	requireShell(t)
	c := Container{VMID: 101, Unprivileged: true}
	hostile := "it's a/file name;with$stuff"
	cmds := map[string]string{
		"write":     c.WriteFileCmd(hostile),
		"append":    c.AppendFileCmd(hostile, 4096),
		"read":      c.ReadFileCmd(hostile),
		"readRange": c.ReadRangeCmd(hostile, 10, 20),
		"stat":      c.StatCmd(hostile),
		"list":      c.ListCmd("/tmp/" + hostile),
		"mkdir":     c.Command("mkdir", hostile),
	}
	for name, cmd := range cmds {
		// Parse only (-n): the generated commands are the subject here.
		if err := exec.CommandContext(t.Context(), "sh", "-n", "-c", cmd).Run(); err != nil {
			t.Errorf("%s produced invalid shell: %v\n%s", name, err, cmd)
		}
	}
}

// TestCommandQuotesAHostilePathIntoOneWord is the injection test: a path
// containing a command substitution must be carried as data.
func TestCommandQuotesAHostilePathIntoOneWord(t *testing.T) {
	got := Container{VMID: 101}.ReadFileCmd("$(touch /tmp/pwned)")
	if strings.Contains(got, "$(touch") && !strings.Contains(got, `'$(touch /tmp/pwned)'`) {
		t.Fatalf("a command substitution reached the command unquoted:\n%s", got)
	}
}
