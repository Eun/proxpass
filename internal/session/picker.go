package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"proxpass/internal/cli"
	"proxpass/internal/models"
)

// errQuit signals that the user declined to pick a guest.
var errQuit = errors.New("quit")

// isReservedLoginName reports whether a login name must never be treated as
// a guest identifier, whatever a guest happens to be called.
//
// Exactly one name is: the administrator's. Guest names come from Proxmox
// discovery and are not under proxpass's control, so without this a guest
// called "admin" would take the one login that is guaranteed to browse.
//
// Client names used to be reserved too, on the reasoning that "ssh
// alice@host" should keep meaning "log in as alice and browse". That is
// withdrawn, for two reasons.
//
// It did not hold. The login name is a REQUEST, not a credential: identity
// comes from the key that authenticated (see ResolveIdentityByKey), and
// authorized-keys offers every key for every servable name. So alice can
// browse under any name she likes -- "admin" always works -- and a guest
// taking her name costs her nothing. Reserving it bought no access she did
// not already have.
//
// And it was surprising in the direction that matters. A client called
// "web" made "ssh web@host" open a picker for EVERYONE, including an
// administrator who meant the container named "web", with nothing on screen
// to explain why. Resolving the name to the guest it names is what the user
// asked for; the picker is still one "ssh admin@host" away.
//
// This takes no context and cannot fail, which is the point: what a name
// means no longer depends on the client list, so there is nothing to look
// up and nothing to go wrong.
func isReservedLoginName(name string) bool {
	// models.NamesEqual rather than strings.EqualFold, matching how the name
	// is folded when stored: see models.FoldName.
	return models.NamesEqual(name, AdminUser)
}

// connectByLoginName connects to the guest named by the login name, or runs
// the picker when the login name does not name one.
//
// "ssh ct100@host" is the shorthand for "ssh -t host ct100": the login name
// is resolved as a guest identifier (VMID, type+VMID or name). This is why
// the directory serves any unused name -- see api.aliasUser.
//
// Resolution is deliberately scoped to the guests this session may REACH,
// not to every guest that exists. The login name is attacker-chosen and
// costs nothing to try, so resolving against all guests would turn this
// into an enumeration oracle: "access denied" for a guest that exists
// against the picker for one that does not, repeated, maps out the estate.
// Scoping also means an ambiguity can only ever name guests the caller is
// already entitled to see, so the disambiguation hint leaks nothing.
//
// Three outcomes, each deliberate:
//
//   - no match: NOT an error. Logging in to browse is the ordinary case
//     ("ssh admin@host", "ssh alice@host"), so a miss falls through to the
//     picker. A guest that exists but is out of reach is indistinguishable
//     from one that does not exist, which is the point.
//   - one match: connect, after the access check below. That check is
//     redundant with the scoping and is kept anyway, so that a future
//     change to either one alone cannot open a hole.
//   - several: report them rather than guess, because connecting to an
//     arbitrary one would put the caller on the wrong machine.
//
// A consequence of the scoping worth being deliberate about: when two
// instances both have a "ct100" and the caller may reach only one, the name
// is unambiguous FOR THEM and connects, while an administrator typing the
// same thing gets an ambiguity error. Two people running one command can
// therefore reach different machines. That is accepted, because the
// alternative -- reporting an ambiguity against a guest the caller may not
// see -- is precisely the disclosure this scoping exists to prevent.
//
// The identity doing all this comes from the KEY, never from the login name
// (see ResolveIdentityByKey), so naming a guest grants nothing: a client
// reaches exactly the guests its access rules already allow.
func (d *Deps) connectByLoginName(ctx context.Context) int {
	name := strings.TrimSpace(d.LoginName)
	if name == "" {
		return d.runPicker(ctx)
	}

	// A reserved name means "browse", even if a guest shares it.
	if isReservedLoginName(name) {
		return d.runPicker(ctx)
	}

	// A node this session may reach wins over a guest of the same name.
	//
	// Checked before guest resolution because the two are not symmetrical:
	// a shadowed GUEST is still reachable, as "ct100@rome", while a node
	// has no such qualified form -- resolving the guest first would make
	// the node unreachable entirely. The instance therefore wins, and
	// nothing becomes unreachable either way.
	//
	// Scoped to accessible instances, like everything else here: a node
	// the caller has no grant for is not a node at all, so it falls
	// through to guest resolution and then the picker on exactly the path
	// a name that matches nothing takes.
	if inst, ok := d.namesANode(ctx, name); ok {
		return d.connectNodeChecked(ctx, inst)
	}

	// Only the guests this session may reach, so that a name it may not
	// reach is simply "not a guest" -- see the enumeration note above.
	guests, err := d.accessibleGuests(ctx)
	if err != nil {
		d.Logger.Printf("%s: %v", d.IdentityName, err)
		d.errf("internal error")
		return 1
	}
	// A login name CAN carry an instance now: "ct100@rome". The suffix is
	// recognized only when it names an instance the caller can actually
	// see, which matters for two reasons.
	//
	// Confidentiality: testing the suffix against every configured
	// instance would be an oracle on instance names -- "x@rome" behaving
	// differently from "x@nope" reveals that "rome" exists. Restricting
	// the predicate to instances hosting a reachable guest means an
	// invisible instance is simply not a separator, so the whole string is
	// tried as one identifier and the usual not-found path shows the
	// picker.
	//
	// Correctness: a client named "tobias@corp" is a legal login name, and
	// must not be read as the guest "tobias" on an instance "corp".
	visible := namedInstances(guests)
	instName, identifier := cli.ParseGuestTarget(name, cli.InstanceLookup(visible))

	// The ambiguity message names every alternative in the "@" form, which
	// a login name can now express; the pool is already filtered, so it can
	// only ever name guests this caller may see.
	guest, _, err := cli.ResolveGuestAndInstance(
		identifier, instName, guestModels(guests), visible)
	switch {
	case errors.Is(err, cli.ErrGuestNotFound):
		// Just a login name, not a guest this session can reach: browse.
		return d.runPicker(ctx)
	case err != nil:
		// Ambiguous, or a storage fault. Either way, say so rather than
		// connecting to an arbitrary match or silently showing the picker.
		d.Logger.Printf("%s: login name as guest: %v", d.IdentityName, err)
		d.errf("%v", err)
		d.errf("or log in by name and pick from the list: ssh %s@<host>",
			d.pickerLoginHint())
		return 1
	}

	// Redundant after the scoping above, and kept on purpose: this is the
	// check that must hold even if the pool is ever widened again. It is
	// now the same call that fetches the credentials, so the two cannot
	// come apart.
	return d.connectChecked(ctx, guest)
}

// pickerLoginHint is a login name the caller can actually use to reach the
// picker.
//
// Suggesting "admin" to a client would be advice it cannot follow, since
// that name grants nothing without an admin key; its own name always works.
func (d *Deps) pickerLoginHint() string {
	if d.IsAdmin {
		return AdminUser
	}
	if n := d.displayName(); n != "" {
		return n
	}
	return AdminUser
}

// runPicker lists the guests the session may reach and connects to the one
// the user selects.
func (d *Deps) runPicker(ctx context.Context) int {
	guests, err := d.accessibleGuests(ctx)
	if err != nil {
		d.Logger.Printf("%s: %v", d.IdentityName, err)
		d.errf("internal error")
		return 1
	}
	if len(guests) == 0 {
		d.errf("no guests available")
		return 1
	}

	rows := newGuestRows(guests)

	chosen, err := d.pick(rows)
	if err != nil {
		if errors.Is(err, errQuit) {
			return 0
		}
		d.Logger.Printf("%s: picker: %v", d.IdentityName, err)
		d.errf("%v", err)
		return 1
	}

	// Credentials are fetched for the chosen guest only, at the moment of
	// connecting, rather than held for every guest in the list.
	return d.connectChecked(ctx, chosen.guest)
}

// pick runs the interactive picker and returns the selected row.
//
// It uses a full-screen alternate-screen view when it has a raw-mode terminal
// to drive, and falls back to a plain numbered prompt otherwise (no PTY, or
// raw mode unavailable) so that scripted use and dumb clients keep working.
func (d *Deps) pick(rows []guestRow) (guestRow, error) {
	if d.Terminal == nil || !d.Terminal.Raw {
		return d.pickNumbered(rows)
	}
	return d.pickInteractive(rows)
}

// pickNumbered is the non-interactive fallback: print the table once and read
// a number.
func (d *Deps) pickNumbered(rows []guestRow) (guestRow, error) {
	out := d.Terminal.UIOut()
	fmt.Fprintf(out, "proxpass — guests available to %s\n\n", d.displayName())
	writeGuestTable(out, rows)
	fmt.Fprintf(out, "\nSelect a guest [1-%d], or q to quit: ", len(rows))

	choice, err := readChoice(d.Terminal.In, len(rows))
	if err != nil {
		fmt.Fprintln(out)
		return guestRow{}, err
	}
	fmt.Fprintln(out)
	row := rows[choice-1]
	if !row.isRunning() {
		return guestRow{}, fmt.Errorf("%s is %s and has no console",
			row.guest.Name, row.guest.Status)
	}
	return row, nil
}

// writeGuestTable renders rows as an aligned, numbered table.
func writeGuestTable(w io.Writer, rows []guestRow) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "  (no guests available)")
		return
	}
	widths := columnWidths(rows)
	fmt.Fprintf(w, "  %*s  %-*s  %-*s  %-*s  %s\n",
		widths.num, "#", widths.id, colID, widths.name, colName,
		widths.status, colStatus, colHost)
	for i, r := range rows {
		fmt.Fprintf(w, "  %*d  %-*s  %-*s  %-*s  %s\n",
			widths.num, i+1, widths.id, r.id, widths.name, r.guest.Name,
			widths.status, r.guest.Status, r.instName)
	}
}

// colWidths are the column widths of the rendered guest table.
type colWidths struct {
	num    int
	id     int
	name   int
	status int
}

// columnWidths measures the table columns.
//
// The widths are computed here rather than with text/tabwriter because
// tabwriter buffers until Flush and writes its padding as tabs when the
// output is not a terminal it can measure; on a raw PTY that produced a
// misaligned table. Plain %-*s padding renders identically everywhere.
func columnWidths(rows []guestRow) colWidths {
	w := colWidths{
		num:    len(fmt.Sprint(len(rows))),
		id:     len(colID),
		name:   len(colName),
		status: len(colStatus),
	}
	for _, r := range rows {
		if n := displayWidth(r.id); n > w.id {
			w.id = n
		}
		if n := displayWidth(r.guest.Name); n > w.name {
			w.name = n
		}
		if n := displayWidth(string(r.guest.Status)); n > w.status {
			w.status = n
		}
	}
	return w
}

// Column headings, shared by the interactive picker and the numbered
// fallback so the two cannot drift apart.
const (
	colID     = "ID"
	colName   = "NAME"
	colStatus = "STATUS"
	colHost   = "HOST"
)

// readChoice reads a selection in [1,max] from r.
func readChoice(r io.Reader, maxChoice int) (int, error) {
	line, err := readLine(r)
	if err != nil {
		// EOF: the client closed the input stream, e.g. ssh without a PTY.
		return 0, errQuit
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.EqualFold(line, "q") || strings.EqualFold(line, "quit") {
		return 0, errQuit
	}
	n := 0
	if _, err := fmt.Sscanf(line, "%d", &n); err != nil || n < 1 || n > maxChoice {
		return 0, fmt.Errorf("invalid selection %q", line)
	}
	return n, nil
}

// readLine reads one line, accepting CR, LF or CRLF as the terminator.
//
// It reads a byte at a time rather than through bufio, because the same
// io.Reader is handed to the guest console afterwards: a buffered reader
// would swallow input that belongs to the console.
func readLine(r io.Reader) (string, error) {
	var (
		b   [1]byte
		out strings.Builder
	)
	for {
		n, err := r.Read(b[:])
		if n > 0 {
			switch b[0] {
			case '\r', '\n':
				return out.String(), nil
			default:
				out.WriteByte(b[0])
			}
		}
		if err != nil {
			if out.Len() > 0 {
				return out.String(), nil
			}
			return "", err
		}
	}
}
