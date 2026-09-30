package session

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"proxpass/internal/models"
)

// runPicker lists the guests the session may reach and connects to the one
// the user selects.
//
// This is deliberately a plain numbered prompt rather than a full-screen TUI:
// the session runs on whatever terminal sshd handed us, and a line-oriented
// prompt behaves correctly on every client, including ones without a PTY.
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

	out := d.Terminal.Out
	fmt.Fprintf(out, "proxpass — guests available to %s\n\n", d.User)
	writeGuestTable(out, guests)
	fmt.Fprintf(out, "\nSelect a guest [1-%d], or q to quit: ", len(guests))

	choice, err := readChoice(d.Terminal.In, len(guests))
	if err != nil {
		if err == errQuit {
			fmt.Fprintln(out)
			return 0
		}
		d.errf("\n%v", err)
		return 1
	}

	guest := guests[choice-1]
	instances, err := d.Repo.ListProxmoxInstances(ctx)
	if err != nil {
		d.Logger.Printf("%s: listing instances: %v", d.User, err)
		d.errf("internal error")
		return 1
	}
	for _, inst := range instances {
		if inst.ID == guest.InstanceID {
			fmt.Fprintln(out)
			return d.attach(guest, inst)
		}
	}
	d.errf("proxmox instance for guest %q not found", guest.Name)
	return 1
}

// errQuit signals that the user declined to pick a guest.
var errQuit = fmt.Errorf("quit")

// scanTerminalLines splits input on CR, LF or CRLF.
//
// The session runs on a PTY in raw mode, which disables ICRNL, so pressing
// Enter delivers a bare "\r". bufio.ScanLines only terminates a line on "\n"
// and would block until EOF, hanging the picker on every real terminal.
func scanTerminalLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i, b := range data {
		if b != '\r' && b != '\n' {
			continue
		}
		// Consume a following LF so CRLF yields a single empty-free token.
		end := i + 1
		if b == '\r' && end < len(data) && data[end] == '\n' {
			end++
		}
		return end, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil // request more data
}

// readChoice reads a selection in [1,max] from r.
func readChoice(r io.Reader, maxChoice int) (int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Split(scanTerminalLines)
	if !scanner.Scan() {
		// EOF: the client closed the input stream, e.g. ssh without a PTY.
		return 0, errQuit
	}
	line := strings.TrimSpace(scanner.Text())
	if line == "" || strings.EqualFold(line, "q") || strings.EqualFold(line, "quit") {
		return 0, errQuit
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > maxChoice {
		return 0, fmt.Errorf("invalid selection %q", line)
	}
	return n, nil
}

// writeGuestTable renders guests as an aligned, numbered table.
func writeGuestTable(w io.Writer, guests []*models.Guest) {
	if len(guests) == 0 {
		fmt.Fprintln(w, "  (no guests available)")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  #\tID\tNAME\tSTATUS")
	for i, g := range guests {
		fmt.Fprintf(tw, "  %d\t%s%d\t%s\t%s\n",
			i+1, g.Type, g.ProxmoxID, g.Name, g.Status)
	}
	_ = tw.Flush()
}
