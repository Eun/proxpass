package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"proxpass/internal/models"
)

// errQuit signals that the user declined to pick a guest.
var errQuit = errors.New("quit")

// runPicker lists the guests the session may reach and connects to the one
// the user selects.
func (d *Deps) runPicker(ctx context.Context) int {
	guests, err := d.accessibleGuests(ctx)
	if err != nil {
		d.Logger.Printf("%s: %v", d.User, err)
		d.errf("internal error")
		return 1
	}
	if len(guests) == 0 {
		d.errf("no guests available")
		return 1
	}

	instances, err := d.Repo.ListProxmoxInstances(ctx)
	if err != nil {
		d.Logger.Printf("%s: listing instances: %v", d.User, err)
		d.errf("internal error")
		return 1
	}
	instNames := make(map[int64]string, len(instances))
	instByID := make(map[int64]*models.ProxmoxInstance, len(instances))
	for _, inst := range instances {
		instNames[inst.ID] = inst.Name
		instByID[inst.ID] = inst
	}

	rows := newGuestRows(guests, instNames)

	chosen, err := d.pick(rows)
	if err != nil {
		if errors.Is(err, errQuit) {
			return 0
		}
		d.Logger.Printf("%s: picker: %v", d.User, err)
		d.errf("%v", err)
		return 1
	}

	inst, ok := instByID[chosen.guest.InstanceID]
	if !ok {
		d.errf("proxmox instance for guest %q not found", chosen.guest.Name)
		return 1
	}
	return d.attach(chosen.guest, inst)
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
	fmt.Fprintf(out, "proxpass — guests available to %s\n\n", d.User)
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
	fmt.Fprintf(w, "  %*s  %-*s  %-*s  %s\n",
		widths.num, "#", widths.id, "ID", widths.name, "NAME", "STATUS")
	for i, r := range rows {
		fmt.Fprintf(w, "  %*d  %-*s  %-*s  %s\n",
			widths.num, i+1, widths.id, r.id, widths.name, r.guest.Name, r.guest.Status)
	}
}

// colWidths are the column widths of the rendered guest table.
type colWidths struct {
	num  int
	id   int
	name int
}

// columnWidths measures the table columns.
//
// The widths are computed here rather than with text/tabwriter because
// tabwriter buffers until Flush and writes its padding as tabs when the
// output is not a terminal it can measure; on a raw PTY that produced a
// misaligned table. Plain %-*s padding renders identically everywhere.
func columnWidths(rows []guestRow) colWidths {
	w := colWidths{num: len(fmt.Sprint(len(rows))), id: len("ID"), name: len("NAME")}
	for _, r := range rows {
		if n := displayWidth(r.id); n > w.id {
			w.id = n
		}
		if n := displayWidth(r.guest.Name); n > w.name {
			w.name = n
		}
	}
	return w
}

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
