// Package session implements the login command that sshd runs for an
// authenticated proxpass client.
//
// sshd is configured with ForceCommand, so this runs instead of a shell no
// matter what the client asked for. The originally requested command, if any,
// arrives in $SSH_ORIGINAL_COMMAND:
//
//	ssh proxpass-host              → no command   → interactive guest picker
//	ssh -t proxpass-host ct100     → "ct100"      → connect straight to a guest
//	ssh proxpass-host guest ls     → "guest ls"   → admin CLI (admins only)
package session

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"proxpass/internal/cli"
	"proxpass/internal/console"
	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/proxmox"
)

// Deps holds everything a session needs.
type Deps struct {
	Repo       db.Repository
	Discoverer proxmox.DiscovererFactory
	Proxier    console.Proxier
	Logger     *log.Logger

	// Terminal is the local terminal provided by sshd.
	Terminal *console.Terminal

	// User is the authenticated login name, as reported by sshd. It is what
	// the client typed, so it is used for the log, where the name that came
	// in is what makes the entry an audit record.
	User string
	// DisplayName is the configured name behind User, which is what the UI
	// shows the user; see Identity.DisplayName for why it can differ.
	//
	// It falls back to User when unset, so a caller that does not know the
	// difference still shows something rather than an empty name.
	DisplayName string
	// IsAdmin grants access to the full admin CLI and to every guest.
	IsAdmin bool
	// ClientID is the database id of the authenticated client; 0 for admins.
	ClientID int64

	// Command is the client's requested command ($SSH_ORIGINAL_COMMAND).
	Command string
}

// Run executes the session and returns the process exit code.
func Run(ctx context.Context, d *Deps) int {
	cmd := strings.TrimSpace(d.Command)

	switch {
	case isHelp(cmd):
		return d.writeHelp(ctx)

	case cmd == "":
		// No command. The login name may itself name a guest -- "ssh
		// ct100@host" -- so try that before falling back to the picker.
		return d.connectByLoginName(ctx)

	case d.IsAdmin:
		return d.runAdmin(ctx, cmd)

	case strings.ContainsRune(cmd, ' '):
		// Non-admins may only name a guest. A multi-word command looks like
		// an attempt to reach the admin CLI.
		d.Logger.Printf("%s: rejected multi-word command %q", d.User, cmd)
		d.errf("access denied: clients may only connect to guests")
		return 1

	default:
		return d.connect(ctx, cmd)
	}
}

// runAdmin handles an admin command: a bare guest identifier connects
// directly, anything else runs through the admin CLI.
func (d *Deps) runAdmin(ctx context.Context, cmd string) int {
	if !strings.ContainsRune(cmd, ' ') {
		// A single token may be a guest; fall through to the CLI when it is
		// not, so "ssh host bogus" reports "unknown command" rather than
		// "guest not found".
		guest, inst, err := d.resolve(ctx, cmd)
		if err == nil {
			return d.attach(guest, inst)
		}
	}

	deps := &cli.Deps{
		Repo:       d.Repo,
		Discoverer: d.Discoverer,
		Out:        d.Terminal.UIOut(),
		ErrOut:     d.Terminal.UIErr(),
	}
	argv := append([]string{"proxpass"}, splitArgs(cmd)...)
	if err := cli.Build(deps).Run(detachValues(ctx), argv); err != nil {
		d.errf("Error: %v", err)
		return 1
	}
	// "guest connect <id>" asks the caller to attach once the CLI returns.
	if deps.ConnectRequest != nil {
		return d.attach(deps.ConnectRequest.Guest, deps.ConnectRequest.Instance)
	}
	return 0
}

// connect resolves a guest identifier, checks access and attaches.
func (d *Deps) connect(ctx context.Context, target string) int {
	guest, inst, err := d.resolve(ctx, target)
	if err != nil {
		d.Logger.Printf("%s: %v", d.User, err)
		d.errf("%v", err)
		return 1
	}
	allowed, err := d.hasAccess(ctx, guest)
	if err != nil {
		d.Logger.Printf("%s: access check failed: %v", d.User, err)
		d.errf("internal error")
		return 1
	}
	if !allowed {
		d.Logger.Printf("%s: access denied to guest %s", d.User, guest.Name)
		d.errf("access denied")
		return 1
	}
	return d.attach(guest, inst)
}

func (d *Deps) attach(guest *models.Guest, inst *models.ProxmoxInstance) int {
	d.Logger.Printf("%s: connecting to %s (%s%d) on %s",
		d.User, guest.Name, guest.Type, guest.ProxmoxID, inst.Name)

	// Announce the escape sequence before handing the terminal to the guest,
	// because an escape hatch nobody knows about is no use when the guest
	// has stopped responding.
	//
	// When a status bar is drawn it carries the hint permanently, so printing
	// it here too would just be duplication. This line is the fallback for
	// the cases where there is no bar: no PTY, a terminal too short to
	// reserve a row, or PROXPASS_DISABLE_STATUSBAR.
	if console.WillDrawBar(d.Terminal) {
		fmt.Fprintf(d.Terminal.UIOut(), "connecting to %s (%s)\n",
			guest.Name, inst.Name)
	} else {
		fmt.Fprintf(d.Terminal.UIOut(), "connecting to %s (%s) -- %s\n",
			guest.Name, inst.Name, console.EscapeHint)
	}

	if err := d.Proxier.Connect(d.Terminal, guest, inst, d.Logger); err != nil {
		d.Logger.Printf("%s: console error: %v", d.User, err)
		d.errf("console error: %v", err)
		return 1
	}
	return 0
}

// resolve turns a user-supplied target into a guest and its instance. The
// target may be qualified as "instance:identifier".
//
// This resolves against EVERY guest, not just the reachable ones, because
// it serves an explicit request: naming a guest that exists but is out of
// reach must say "access denied" rather than "not found". The login-name
// path deliberately does the opposite; see connectByLoginName.
func (d *Deps) resolve(ctx context.Context, target string) (*models.Guest, *models.ProxmoxInstance, error) {
	instName, identifier := cli.ParseGuestTarget(target)
	guests, err := d.Repo.ListGuests(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("listing guests: %w", err)
	}
	instances, err := d.Repo.ListProxmoxInstances(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("listing instances: %w", err)
	}
	return cli.ResolveGuestAndInstance(identifier, instName, guests, instances)
}

// hasAccess reports whether the session may reach the guest. Admins may
// always connect.
func (d *Deps) hasAccess(ctx context.Context, guest *models.Guest) (bool, error) {
	if d.IsAdmin {
		return true, nil
	}
	ok, err := d.Repo.HasAccess(ctx, d.ClientID, guest.ID)
	if err != nil {
		return false, fmt.Errorf("checking access: %w", err)
	}
	return ok, nil
}

// accessibleGuests returns the guests this session is allowed to reach.
func (d *Deps) accessibleGuests(ctx context.Context) ([]*models.Guest, error) {
	guests, err := d.Repo.ListGuests(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing guests: %w", err)
	}
	if d.IsAdmin {
		return guests, nil
	}
	out := make([]*models.Guest, 0, len(guests))
	for _, g := range guests {
		ok, err := d.Repo.HasAccess(ctx, d.ClientID, g.ID)
		if err != nil {
			return nil, fmt.Errorf("checking access: %w", err)
		}
		if ok {
			out = append(out, g)
		}
	}
	return out, nil
}

// splitArgs does a shell-like split that understands single and double
// quotes.
//
// The local shell already removed one layer of quoting before ssh sent the
// command, but arguments that legitimately contain spaces — an SSH public key
// passed to "client add --key" is the common case — arrive here still quoted.
// Splitting on whitespace alone would tear such a key into fragments and the
// command would fail with "no key found".
func splitArgs(s string) []string {
	var (
		args  []string
		cur   strings.Builder
		quote rune
	)
	for _, r := range s {
		switch {
		case quote != 0:
			// Inside a quoted run: only the matching quote ends it.
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ' ' || r == '\t':
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}

func isHelp(cmd string) bool {
	switch strings.ToLower(strings.TrimSpace(cmd)) {
	case "help", "--help", "-h":
		return true
	}
	return false
}

// writeHelp prints usage. Admins get the real CLI help so it can never drift
// from the actual command set.
func (d *Deps) writeHelp(ctx context.Context) int {
	if d.IsAdmin {
		deps := &cli.Deps{
			Repo:       d.Repo,
			Discoverer: d.Discoverer,
			Out:        d.Terminal.UIErr(),
			ErrOut:     d.Terminal.UIErr(),
		}
		_ = cli.Build(deps).Run(detachValues(ctx), []string{"proxpass", "--help"})
		return 0
	}

	w := d.Terminal.UIErr()
	fmt.Fprintf(w, "proxpass — connect to a Proxmox guest\n\n")
	// The display name, not the login name: this is an instruction to be
	// retyped, so it has to name an identity rather than echo back an
	// alias that happens to have resolved this time.
	fmt.Fprintf(w, "  ssh %s@<host>              choose a guest interactively\n", d.displayName())
	fmt.Fprintf(w, "  ssh -t %s@<host> <guest>   connect directly\n\n", d.displayName())
	fmt.Fprintf(w, "A guest may be named by VMID (100), type+VMID (ct100, vm200),\n")
	fmt.Fprintf(w, "name (webserver), or instance-qualified (rome:ct101).\n\n")

	guests, err := d.accessibleGuests(ctx)
	if err != nil {
		return 1
	}
	instances, err := d.Repo.ListProxmoxInstances(ctx)
	if err != nil {
		return 1
	}
	instNames := make(map[int64]string, len(instances))
	for _, inst := range instances {
		instNames[inst.ID] = inst.Name
	}
	writeGuestTable(w, newGuestRows(guests, instNames))
	return 0
}

// displayName is the name the UI shows for this session.
//
// Every user-facing mention of "who am I" goes through here rather than
// reading DisplayName directly, so a caller that only set User -- a test, or
// anything constructing Deps by hand -- still gets a name instead of a blank.
func (d *Deps) displayName() string {
	if d.DisplayName != "" {
		return d.DisplayName
	}
	return d.User
}

// errf reports an error to the user on stderr.
func (d *Deps) errf(format string, args ...any) {
	var w io.Writer = os.Stderr
	if d.Terminal != nil && d.Terminal.Err != nil {
		w = d.Terminal.UIErr()
	}
	fmt.Fprintf(w, format+"\n", args...)
}
