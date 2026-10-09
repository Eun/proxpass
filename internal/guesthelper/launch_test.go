package guesthelper_test

import (
	"os/exec"
	"strings"
	"testing"

	"proxpass/internal/guesthelper"
)

// unameAMD64 is what `uname -m' prints on a 64-bit x86 node.
const unameAMD64 = "x86_64"

func TestParseArch(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want guesthelper.Arch
		bad  bool
	}{
		{in: unameAMD64, want: guesthelper.ArchAMD64},
		{in: "amd64", want: guesthelper.ArchAMD64},
		{in: "aarch64", want: guesthelper.ArchARM64},
		{in: "arm64", want: guesthelper.ArchARM64},
		// Real uname output carries a trailing newline.
		{in: unameAMD64 + "\n", want: guesthelper.ArchAMD64},
		{in: "  aarch64  \n", want: guesthelper.ArchARM64},
		{in: "X86_64", want: guesthelper.ArchAMD64},
		// 32-bit arm is a real machine type and NOT something proxpass
		// builds for, so it must be refused rather than guessed at.
		{in: "armv7l", bad: true},
		{in: "riscv64", bad: true},
		{in: "", bad: true},
	} {
		got, err := guesthelper.ParseArch(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("ParseArch(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseArch(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseArch(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestStagePathSeparatesArches pins that the two architectures never share a
// file: a cluster with mixed nodes would otherwise have them overwrite each
// other, and the failure would be an exec format error on whichever node
// lost the race.
func TestStagePathSeparatesArches(t *testing.T) {
	amd := guesthelper.StagePath(guesthelper.ArchAMD64)
	arm := guesthelper.StagePath(guesthelper.ArchARM64)
	if amd == arm {
		t.Fatalf("both architectures stage to %q", amd)
	}
	for _, p := range []string{amd, arm} {
		if !strings.HasPrefix(p, guesthelper.StageDir+"/") {
			t.Errorf("%q is not under %q", p, guesthelper.StageDir)
		}
	}
}

// TestLaunchCommandFlags pins the flags that were settled against a real
// node. Each one is load-bearing and a silent removal would reintroduce a
// bug that is expensive to rediscover.
func TestLaunchCommandFlags(t *testing.T) {
	cmd := guesthelper.LaunchCommand(127, guesthelper.ArchAMD64, true)

	for _, want := range []string{
		"nsenter",
		" -m ",         // mount namespace: paths resolve inside the container
		" -r ",         // its root: an absolute symlink cannot escape to the node
		" -p ",         // its PID namespace: without this the exec is ENOENT
		" -U ",         // its user namespace
		"-S 0", "-G 0", // as root inside
		"lxc-info",
		"exec ",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("missing %q in:\n%s", want, cmd)
		}
	}

	// -r and -w take OPTIONAL arguments, so a separated value is parsed as
	// the program to run. "nsenter -r /" once made every transfer fail
	// with "failed to execute /: Permission denied".
	for _, bad := range []string{"-r /", "-w /"} {
		if strings.Contains(cmd, bad) {
			t.Errorf("found %q, which makes / the program:\n%s", bad, cmd)
		}
	}
}

// TestLaunchCommandPrivileged pins that a privileged container does NOT get
// the user-namespace flags: entering it fails with EINVAL because the caller
// is already a member.
func TestLaunchCommandPrivileged(t *testing.T) {
	cmd := guesthelper.LaunchCommand(100, guesthelper.ArchARM64, false)
	if strings.Contains(cmd, " -U ") {
		t.Errorf("privileged container got -U:\n%s", cmd)
	}
	if !strings.Contains(cmd, " -m ") || !strings.Contains(cmd, " -p ") {
		t.Errorf("privileged container lost -m or -p:\n%s", cmd)
	}
}

// TestGeneratedCommandsAreValidShell runs the generated commands through
// `sh -n', which catches a quoting mistake that would otherwise only show up
// against a live node.
func TestGeneratedCommandsAreValidShell(t *testing.T) {
	requireShell(t)
	for name, cmd := range map[string]string{
		"launch":     guesthelper.LaunchCommand(127, guesthelper.ArchAMD64, true),
		"stage":      guesthelper.StageCommand(guesthelper.ArchAMD64),
		"stage-arm":  guesthelper.StageCommand(guesthelper.ArchARM64),
		"arch-probe": guesthelper.ArchCommand,
	} {
		c := exec.CommandContext(t.Context(), "sh", "-n")
		c.Stdin = strings.NewReader(cmd)
		if out, err := c.CombinedOutput(); err != nil {
			t.Errorf("%s is not valid shell: %v\n%s\n%s", name, err, out, cmd)
		}
	}
}

// TestStageCommandIsIdempotent pins that a node which already has the binary
// is not made to receive it again: the whole point of caching it is that a
// two-megabyte push per transfer would cost more than the sessions the
// helper removes.
func TestStageCommandIsIdempotent(t *testing.T) {
	cmd := guesthelper.StageCommand(guesthelper.ArchAMD64)
	if !strings.Contains(cmd, "-x ") {
		t.Errorf("no existence check, so the binary is pushed every time:\n%s", cmd)
	}
	// It must still drain stdin when it skips the write, or the writer
	// blocks forever on a pipe nobody is reading.
	if !strings.Contains(cmd, "/dev/null") {
		t.Errorf("the skip path does not consume stdin, which deadlocks:\n%s", cmd)
	}
	// The write must be atomic, or a concurrent transfer can exec a
	// half-written file.
	if !strings.Contains(cmd, "mv -f") {
		t.Errorf("the staged file is not renamed into place:\n%s", cmd)
	}
}

func requireShell(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
}
