package console

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// testLabel stands in for a guest label in bar-layout tests.
const (
	testLabel = "guest"
	testHint  = "hint"
)

// lockedBuffer collects bar output from the draw goroutine.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// waitForBar polls until want appears, so tests do not depend on the repaint
// tick landing within a fixed sleep.
func waitForBar(t *testing.T, buf *lockedBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in bar output; got %q", want, buf.String())
}

// --- alternate screen detection ---

// The bar must hide for every alternate-screen mode, not just the modern
// one, or it paints over older full-screen applications.
func TestModeFilterDetectsEveryAltScreenMode(t *testing.T) {
	for _, mode := range []string{"47", "1047", "1049"} {
		t.Run(mode, func(t *testing.T) {
			var m modeFilter
			if !m.Observe([]byte("\x1b[?" + mode + "h")) {
				t.Fatalf("?%s h was not reported as a change", mode)
			}
			if !m.AltScreen() {
				t.Errorf("?%s h did not enable alt screen", mode)
			}
			if !m.Observe([]byte("\x1b[?" + mode + "l")) {
				t.Fatalf("?%s l was not reported as a change", mode)
			}
			if m.AltScreen() {
				t.Errorf("?%s l did not disable alt screen", mode)
			}
		})
	}
}

// A single sequence may set several modes at once, and the "?" private
// marker applies to all of them. Testing only the first parameter misses
// the alt-screen bit when it is not listed first.
func TestModeFilterHandlesMultiParameterModeSets(t *testing.T) {
	for _, seq := range []string{
		"\x1b[?1049;1000h", // alt screen first
		"\x1b[?1000;1049h", // alt screen second: needs marker propagation
		"\x1b[?1000;1006;1049h",
	} {
		t.Run(seq, func(t *testing.T) {
			var m modeFilter
			m.Observe([]byte(seq))
			if !m.AltScreen() {
				t.Errorf("%q did not enable alt screen", seq)
			}
		})
	}
}

// Modes without the private marker are ANSI modes and must not be confused
// with the private alt-screen modes that share their numbers.
func TestModeFilterIgnoresNonPrivateModes(t *testing.T) {
	var m modeFilter
	m.Observe([]byte("\x1b[47h"))
	if m.AltScreen() {
		t.Error("non-private 47h must not enable alt screen")
	}
}

// Escape sequences arrive split across reads, so the detection has to carry
// state between calls.
func TestModeFilterHandlesSequenceSplitAcrossWrites(t *testing.T) {
	var m modeFilter
	for _, chunk := range []string{"\x1b", "[?10", "49", "h"} {
		m.Observe([]byte(chunk))
	}
	if !m.AltScreen() {
		t.Error("alt screen not detected when the sequence was split")
	}
}

// One byte at a time is the worst case and must still work.
func TestModeFilterHandlesOneByteAtATime(t *testing.T) {
	var m modeFilter
	for _, b := range []byte("\x1b[?1049h") {
		m.Observe([]byte{b})
	}
	if !m.AltScreen() {
		t.Error("alt screen not detected byte-by-byte")
	}
}

// An unterminated escape must not buffer without bound.
func TestModeFilterBoundsPartialSequences(t *testing.T) {
	var m modeFilter
	m.Observe([]byte("\x1b[" + strings.Repeat("1", maxPartialEscape*2)))
	if len(m.partial) > maxPartialEscape {
		t.Errorf("partial buffer grew to %d bytes, want <= %d",
			len(m.partial), maxPartialEscape)
	}
}

// Ordinary output must not be mistaken for a mode change.
func TestModeFilterIgnoresOrdinaryOutput(t *testing.T) {
	var m modeFilter
	if m.Observe([]byte("total 42\nhello \x1b[31mred\x1b[0m\n")) {
		t.Error("ordinary output reported a mode change")
	}
	if m.AltScreen() {
		t.Error("ordinary output enabled alt screen")
	}
}

// Repeating the same mode is not a change, so it must not force repaints.
func TestModeFilterReportsOnlyTransitions(t *testing.T) {
	var m modeFilter
	if !m.Observe([]byte("\x1b[?1049h")) {
		t.Fatal("first enable should be a change")
	}
	if m.Observe([]byte("\x1b[?1049h")) {
		t.Error("repeating the same mode must not report a change")
	}
}

// --- width and truncation ---

func TestCellWidthCountsDisplayColumns(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want int
	}{
		{"ascii", "hello", 5},
		{"empty", "", 0},
		{"cjk is double width", "日本", 4},
		{"mixed", "a日b", 4},
		{"combining mark is zero width", "e\u0301", 1},
		{"control bytes are zero width", "a\x01b", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cellWidth(tc.in); got != tc.want {
				t.Errorf("cellWidth(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// Truncation must never split a rune: a byte-wise cut produces mojibake.
func TestTruncateCellsNeverSplitsARune(t *testing.T) {
	const s = "日本語"
	for cols := range 7 {
		got := truncateCells(s, cols)
		if !utf8ValidString(got) {
			t.Errorf("truncateCells(%q, %d) = %q, which is not valid UTF-8", s, cols, got)
		}
		if w := cellWidth(got); w > cols {
			t.Errorf("truncateCells(%q, %d) = %q, width %d exceeds %d", s, cols, got, w, cols)
		}
	}
}

func utf8ValidString(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}

// The bar must always be exactly the terminal width: shorter leaves stale
// characters from whatever was there before, longer wraps onto the next row
// and scrolls the screen.
func TestBarTextIsAlwaysExactlyTerminalWidth(t *testing.T) {
	for _, tc := range []struct {
		name        string
		left, right string
		cols        int
	}{
		{"fits easily", testLabel, testHint, 40},
		{"exact fit", "abcde", "fghij", 11},
		{"left too long", strings.Repeat("x", 50), testHint, 20},
		{"narrow", testLabel, testHint, 8},
		{"very narrow", testLabel, testHint, 3},
		{"wide runes", "日本語の名前", "ヒント", 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := barText(tc.left, tc.right, tc.cols)
			if w := cellWidth(got); w != tc.cols {
				t.Errorf("barText(%q,%q,%d) width = %d, want %d (%q)",
					tc.left, tc.right, tc.cols, w, tc.cols, got)
			}
		})
	}
}

// --- drawing behavior ---

// A bar whose text has not changed must not be rewritten, because an
// unconditional repaint is what makes a bar flicker.
func TestStatusBarSkipsUnchangedRepaints(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 40, 24)
	b.SetText(testLabel, testHint)
	b.Start()
	defer b.Stop()

	waitForBar(t, buf, "guest")
	first := len(buf.String())

	// Many redraw requests with identical content.
	for range 20 {
		b.request()
	}
	time.Sleep(300 * time.Millisecond)

	if grew := len(buf.String()) - first; grew != 0 {
		t.Errorf("unchanged bar was rewritten (%d extra bytes)", grew)
	}
}

// Changing the text must repaint.
func TestStatusBarRedrawsWhenTextChanges(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 40, 24)
	b.SetText("first", "")
	b.Start()
	defer b.Stop()

	waitForBar(t, buf, "first")
	b.SetText("second", "")
	waitForBar(t, buf, "second")
}

// A burst of changes must collapse into far fewer draws than requests: this
// is the throttle that keeps a chatty guest from pinning the CPU.
func TestStatusBarCoalescesRapidUpdates(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 40, 24)
	b.Start()
	defer b.Stop()

	const updates = 200
	for i := range updates {
		b.SetText(strings.Repeat("x", i%7+1), "")
	}
	time.Sleep(200 * time.Millisecond)

	draws := strings.Count(buf.String(), "\x1b7")
	if draws >= updates/4 {
		t.Errorf("%d draws for %d updates: updates are not being coalesced",
			draws, updates)
	}
	if draws == 0 {
		t.Error("no draws at all")
	}
}

// The bar must install a scroll region that excludes its own row, and must
// reserve exactly one row from the guest.
func TestStatusBarReservesExactlyOneRow(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 80, 24)
	if got := b.GuestRows(); got != 23 {
		t.Errorf("GuestRows() = %d, want 23", got)
	}
	b.Start()
	defer b.Stop()
	if !strings.Contains(buf.String(), "\x1b[1;23r") {
		t.Errorf("scroll region not set to rows 1-23: %q", buf.String())
	}
}

// Stop must reset the scroll region, or the user's shell is left with a
// restricted scrolling area after disconnecting.
func TestStatusBarStopResetsScrollRegion(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 80, 24)
	b.Start()
	waitForBar(t, buf, "\x1b[1;23r")
	b.Stop()
	if !strings.Contains(buf.String(), "\x1b[r") {
		t.Errorf("scroll region was not reset on Stop: %q", buf.String())
	}
}

// On entering the alternate screen the bar must release the scroll region and
// stop drawing, so a full-screen application gets the whole terminal.
func TestStatusBarYieldsToFullScreenApplications(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 40, 24)
	b.SetText(testLabel, testHint)
	b.Start()
	defer b.Stop()

	waitForBar(t, buf, "guest")

	// vim starts.
	b.Observe([]byte("\x1b[?1049h"))
	waitForBar(t, buf, "\x1b[r")
	mark := len(buf.String())

	// While it owns the screen, nothing may be drawn.
	for range 10 {
		b.SetText("should-not-appear", "")
	}
	time.Sleep(250 * time.Millisecond)
	if after := buf.String()[mark:]; strings.Contains(after, "should-not-appear") {
		t.Errorf("bar drew while a full-screen application was active: %q", after)
	}

	// vim exits: the bar must come back without waiting for the idle timer.
	b.Observe([]byte("\x1b[?1049l"))
	waitForBar(t, buf, "should-not-appear")
}

// Resizing must reinstall the scroll region at the new height and repaint,
// otherwise the bar is stranded on a row that is no longer the bottom one.
func TestStatusBarResizeReinstallsScrollRegion(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 80, 24)
	b.SetText("guest", "")
	b.Start()
	defer b.Stop()
	waitForBar(t, buf, "\x1b[1;23r")

	if got := b.Resize(100, 40); got != 39 {
		t.Errorf("Resize returned %d guest rows, want 39", got)
	}
	waitForBar(t, buf, "\x1b[1;39r")
	// And it must repaint at the new position.
	waitForBar(t, buf, "\x1b[40;1H")
}

// A terminal too short for a bar must be left completely alone rather than
// given a one-row scroll region.
func TestStatusBarDisablesItselfOnTinyTerminals(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 80, 2)
	if got := b.GuestRows(); got != 2 {
		t.Errorf("GuestRows() = %d, want the full 2 rows", got)
	}
	b.Start()
	b.SetText(testLabel, testHint)
	time.Sleep(150 * time.Millisecond)
	b.Stop()
	if out := buf.String(); out != "" {
		t.Errorf("a tiny terminal must not be touched, wrote %q", out)
	}
}

// Observe must not alter the stream it inspects: guest output has to reach
// the terminal byte for byte.
func TestStatusBarObserveDoesNotModifyData(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 40, 24)
	b.Start()
	defer b.Stop()

	data := []byte("before\x1b[?1049hafter")
	orig := string(data)
	b.Observe(data)
	if string(data) != orig {
		t.Errorf("Observe modified its input: %q became %q", orig, string(data))
	}
}

// The cursor must be saved and restored with DECSC/DECRC, not the ANSI.SYS
// pair, which collides with DECSLRM on terminals that support margins.
func TestStatusBarUsesDECSCNotANSISYSCursorSave(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 40, 24)
	b.SetText("guest", "")
	b.Start()
	defer b.Stop()
	waitForBar(t, buf, "guest")

	out := buf.String()
	if !strings.Contains(out, "\x1b7") || !strings.Contains(out, "\x1b8") {
		t.Errorf("bar does not use DECSC/DECRC: %q", out)
	}
	if strings.Contains(out, "\x1b[s") || strings.Contains(out, "\x1b[u") {
		t.Errorf("bar uses ANSI.SYS cursor save/restore: %q", out)
	}
}

// --- surviving things that wipe the bar's row ---

// A scroll region confines scrolling, not erasure: ED addresses the whole
// screen and takes the bar's row with it. Ctrl+L is the everyday way to hit
// this, because the shell answers it with ED.
func TestModeFilterDetectsEraseOfTheBarRow(t *testing.T) {
	for _, tc := range []struct {
		name string
		seq  string
		want bool
	}{
		{"ED 2J, what Ctrl+L produces", "\x1b[2J", true},
		{"ED 0J, cursor to end of screen", "\x1b[0J", true},
		{"ED with no parameter", "\x1b[J", true},
		{"ED 3J, screen and scrollback", "\x1b[3J", true},
		// 1J erases up to the cursor, which is always inside the scroll
		// region and so above the bar.
		{"ED 1J cannot reach the bar row", "\x1b[1J", false},
		// EL erases within a line; the cursor cannot be on the bar's row.
		{"EL 2K stays on the cursor's line", "\x1b[2K", false},
		{"ordinary text", "hello world", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m modeFilter
			if got := m.Observe([]byte(tc.seq)); got != tc.want {
				t.Errorf("Observe(%q) = %v, want %v", tc.seq, got, tc.want)
			}
		})
	}
}

// The bar must come back after the guest erases the screen. Without this it
// stays blank forever, because its text has not changed and the
// unchanged-repaint skip suppresses the draw.
func TestStatusBarRepaintsAfterEraseDisplay(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 40, 24)
	b.SetText(testLabel, testHint)
	b.Start()
	defer b.Stop()

	waitForBar(t, buf, testLabel)
	mark := len(buf.String())

	// What a shell sends for Ctrl+L.
	b.Observe([]byte("\x1b[H\x1b[2J"))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String()[mark:], testLabel) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("bar did not repaint after an erase; wrote only %q", buf.String()[mark:])
}

// RIS resets the scroll region as well as the screen, so repainting the row
// is not enough: the region has to be reinstalled or the guest will scroll
// over the bar.
func TestStatusBarReinstallsRegionAfterTerminalReset(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 40, 24)
	b.SetText(testLabel, testHint)
	b.Start()
	defer b.Stop()

	waitForBar(t, buf, "\x1b[1;23r")
	mark := len(buf.String())

	// "reset" / "tput reset" in the guest.
	b.Observe([]byte("\x1bc"))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		after := buf.String()[mark:]
		if strings.Contains(after, "\x1b[1;23r") && strings.Contains(after, testLabel) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("region was not reinstalled after a reset; wrote only %q",
		buf.String()[mark:])
}

// A reset leaves the cursor at the top-left of an unrestricted screen, so it
// has to be put back inside the region.
func TestStatusBarHomesCursorAfterTerminalReset(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 40, 24)
	b.SetText(testLabel, testHint)
	b.Start()
	defer b.Stop()

	waitForBar(t, buf, "\x1b[1;23r")
	mark := len(buf.String())

	b.Observe([]byte("\x1bc"))
	waitForBar(t, buf, testLabel)

	if after := buf.String()[mark:]; !strings.Contains(after, "\x1b[1;1H") {
		t.Errorf("cursor was not homed into the region after a reset: %q", after)
	}
}

// An erase while a full-screen application owns the screen must not bring the
// bar back: the application is erasing its own screen, and the bar has no
// row to draw on.
func TestStatusBarStaysHiddenWhenFullScreenAppErases(t *testing.T) {
	buf := &lockedBuffer{}
	b := NewStatusBar(buf, 40, 24)
	b.SetText(testLabel, testHint)
	b.Start()
	defer b.Stop()

	waitForBar(t, buf, testLabel)
	b.Observe([]byte("\x1b[?1049h"))
	waitForBar(t, buf, "\x1b[r")
	mark := len(buf.String())

	// vim clearing and redrawing its own screen.
	for range 5 {
		b.Observe([]byte("\x1b[2J\x1b[H"))
	}
	time.Sleep(250 * time.Millisecond)

	if after := buf.String()[mark:]; strings.Contains(after, testLabel) {
		t.Errorf("bar drew while a full-screen application was erasing: %q", after)
	}
}
