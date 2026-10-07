package session

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"proxpass/internal/cli"
	"proxpass/internal/console"
	"proxpass/internal/guestfs"
	"proxpass/internal/models"
)

// namesAGuest reports whether the login name addresses a guest this session
// may reach.
//
// This is what decides between "run this in the container" and "this is a
// proxpass command". The rule is the login name: `ssh ct100@host whoami' is
// addressed to ct100, and `ssh alice@host guest ls' is addressed to proxpass.
// A reserved name -- the administrator's, or any configured client's --
// always means proxpass, so a client cannot lose access to the CLI by sharing
// a name with a guest.
//
// Resolution is the same as the console's, scoped to the guests this session
// may reach, so a name it may not reach is simply not a guest and the command
// goes to proxpass as before.
func (d *Deps) namesAGuest(ctx context.Context) (*models.Guest, bool) {
	name := trimmedLoginName(d)
	if name == "" {
		return nil, false
	}
	reserved, err := d.isReservedLoginName(ctx, name)
	if err != nil || reserved {
		return nil, false
	}
	guest, err := d.resolveLoginNameGuest(ctx, name)
	if err != nil {
		// Only an EXACT, single match routes the command to a container.
		//
		// A miss is the ordinary case -- "ssh alice@host guest ls" -- and
		// must fall through to proxpass's own CLI, which is what the caller
		// does with a false return.
		//
		// An ambiguity falls through too, deliberately. Guessing which of
		// several guests was meant would run the command on the wrong
		// machine, and silence is better than that; the name resolves
		// identically for "ssh ct100@host" with no command, so the user
		// gets the ambiguity listed there with the alternatives spelled
		// out.
		return nil, false
	}
	return guest, true
}

// runGuestCommand runs cmd inside the guest named by the login name.
//
// This is what makes `ssh ct100@host whoami' behave like an ordinary ssh: the
// command runs in the container, its output comes back on the right stream,
// and its exit status becomes this process's.
func (d *Deps) runGuestCommand(ctx context.Context, guest *models.Guest, command string) int {
	info, err := d.Dir.Connect(ctx, guest.ID)
	if err != nil {
		if errors.Is(err, ErrAccessDenied) {
			d.errf("access denied")
			return 1
		}
		d.Logger.Printf("%s: connect %s: %v", d.IdentityName, guest.Name, err)
		d.errf("internal error")
		return 1
	}
	inst := info.Instance

	// Only containers. A VM has no namespace to enter, and its guest agent
	// is a different mechanism with different limits.
	if guest.Type != models.GuestTypeCT {
		d.errf("%s is a virtual machine; running commands is supported for containers only",
			guest.Name)
		return 1
	}
	if inst.SSHHost == "" {
		d.errf("instance %s has no ssh host configured", inst.Name)
		return 1
	}

	runner, err := console.DialNode(inst, info.SSHKey, d.Logger)
	if err != nil {
		d.Logger.Printf("%s: %v", d.IdentityName, err)
		d.errf("cannot reach %s: %v", inst.SSHHost, err)
		return 1
	}
	defer func() { _ = runner.Close() }()

	container := guestfs.Container{VMID: guest.ProxmoxID, Unprivileged: true}

	d.Logger.Printf("%s: command on %s (%s%d) on %s",
		d.IdentityName, guest.Name, guest.Type, guest.ProxmoxID, inst.Name)

	term := d.Terminal
	// Mirror the client's own request. sshd gave this process a PTY exactly
	// when the client asked for one, and Terminal.Raw records that, so the
	// command gets a terminal inside the container on the same terms it
	// would over a direct ssh -- and a piped command keeps its streams
	// separate and its bytes unmodified.
	code, err := runner.Exec(&console.ExecOptions{
		Command: container.ShellCmd(command),
		PTY:     term.Raw,
		Term:    term.Term,
		Width:   term.Width,
		Height:  term.Height,
		Resizes: term.Resizes,
		Stdin:   term.In,
		Stdout:  term.Out,
		Stderr:  term.Err,
	})
	if err != nil {
		d.Logger.Printf("%s: command on %s: %v", d.IdentityName, guest.Name, err)
		d.errf("%v", err)
		return 1
	}
	return code
}

// resolveLoginNameGuest resolves a login name to one reachable guest.
//
// The same resolution the console uses for "ssh ct100@host", via the same
// helpers, so the two cannot drift: scoped to the guests this session may
// reach, so a name it may not reach is simply not a guest, and an ambiguity
// can only ever name guests the caller already sees. It also accepts the
// "ct100@rome" form for an instance-qualified name.
func (d *Deps) resolveLoginNameGuest(ctx context.Context, name string) (*models.Guest, error) {
	guests, err := d.accessibleGuests(ctx)
	if err != nil {
		return nil, err
	}
	visible := namedInstances(guests)
	instName, identifier := cli.ParseGuestTarget(name, cli.InstanceLookup(visible))
	guest, _, err := cli.ResolveGuestAndInstance(
		identifier, instName, guestModels(guests), visible)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, err)
	}
	return guest, nil
}

// trimmedLoginName is the login name with surrounding space removed.
func trimmedLoginName(d *Deps) string { return strings.TrimSpace(d.LoginName) }
