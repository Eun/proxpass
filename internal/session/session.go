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

// cliProgName is argv[0] for both CLI trees; urfave/cli prints it in
// usage and error messages.
const cliProgName = "proxpass"

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

	default:
		return d.runClient(ctx, cmd)
	}
}

// runClient handles a command from a non-admin client.
//
// Clients get a small CLI of their own rather than a bare guest identifier.
// The identifier form used to live here ("ssh host ct100"), and is gone: a
// guest is now named either as the login name or through "guest connect",
// which means one syntax instead of a bare token that had to be
// distinguished from a command by guessing.
func (d *Deps) runClient(ctx context.Context, cmd string) int {
	guests, err := d.accessibleGuests(ctx)
	if err != nil {
		d.Logger.Printf("%s: %v", d.User, err)
		d.errf("internal error")
		return 1
	}
	instances, err := d.Repo.ListProxmoxInstances(ctx)
	if err != nil {
		d.Logger.Printf("%s: listing instances: %v", d.User, err)
		d.errf("internal error")
		return 1
	}

	deps := &cli.ClientDeps{
		Deps: &cli.Deps{
			Repo:   d.Repo,
			Out:    d.Terminal.UIOut(),
			ErrOut: d.Terminal.UIErr(),
		},
		// Pre-filtered: no command in the client tree can reach a guest
		// outside this set, because none of them can see one.
		Guests:    guests,
		Instances: instances,
	}
	argv := append([]string{cliProgName}, splitArgs(cmd)...)
	if err := cli.BuildClient(deps).Run(detachValues(ctx), argv); err != nil {
		d.Logger.Printf("%s: client cli: %v", d.User, err)
		d.errf("Error: %v", err)
		return 1
	}
	if deps.ConnectRequest != nil {
		// The access check is redundant with the filtered pool and kept
		// anyway, so that widening either one alone cannot open a hole.
		return d.connectChecked(ctx, deps.ConnectRequest.Guest,
			deps.ConnectRequest.Instance)
	}
	return 0
}

// connectChecked attaches to a guest after confirming the session may
// reach it.
func (d *Deps) connectChecked(
	ctx context.Context, guest *models.Guest, inst *models.ProxmoxInstance,
) int {
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

// runAdmin runs an admin command through the admin CLI.
//
// A bare guest identifier used to connect directly from here ("ssh host
// ct100"). That is gone: a single token had to be guessed at -- guest or
// mistyped command? -- and the guess leaked, because "ssh host bogus"
// reported "unknown command" while "ssh host ct999" reported a resolution
// failure. A guest is now named either as the login name or through
// "guest connect", so nothing has to be guessed.
func (d *Deps) runAdmin(ctx context.Context, cmd string) int {
	deps := &cli.Deps{
		Repo:       d.Repo,
		Discoverer: d.Discoverer,
		Out:        d.Terminal.UIOut(),
		ErrOut:     d.Terminal.UIErr(),
	}
	argv := append([]string{cliProgName}, splitArgs(cmd)...)
	if err := cli.Build(deps).Run(detachValues(ctx), argv); err != nil {
		d.errf("Error: %v", err)
		return 1
	}
	// "guest connect <id>" asks the caller to attach once the CLI returns.
	if deps.ConnectRequest != nil {
		return d.connectChecked(ctx, deps.ConnectRequest.Guest,
			deps.ConnectRequest.Instance)
	}
	return 0
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
	fmt.Fprintf(w, "  ssh %s@<host>                            choose a guest interactively\n",
		d.displayName())
	fmt.Fprintf(w, "  ssh <guest>@<host>                       connect directly\n")
	fmt.Fprintf(w, "  ssh -t %s@<host> guest connect <guest>   connect via the CLI\n",
		d.displayName())
	fmt.Fprintf(w, "  ssh %s@<host> guest ls                   list what you may reach\n\n",
		d.displayName())
	fmt.Fprintf(w, "A guest may be named by VMID (100), type+VMID (ct100, vm200),\n")
	fmt.Fprintf(w, "name (webserver), or instance-qualified (ct101@rome).\n\n")

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
