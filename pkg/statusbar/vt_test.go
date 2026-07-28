package statusbar_test

import (
	"bytes"
	"strings"
	"testing"

	vt10x "github.com/hinshun/vt10x"

	"proxpass/pkg/statusbar"
)

// vtScreen is a thin helper around vt10x.Terminal for test assertions.
type vtScreen struct {
	vt10x.Terminal
	cols int
	rows int
}

func newVT(cols, rows int) *vtScreen {
	return &vtScreen{
		Terminal: vt10x.New(vt10x.WithSize(cols, rows)),
		cols:     cols,
		rows:     rows,
	}
}

// feed parses raw bytes (including escape sequences) into the virtual terminal.
// Write() acquires the internal lock itself; do NOT hold the public Lock().
func (v *vtScreen) feed(data []byte) {
	_, _ = v.Write(data)
}

// rowText returns the visible text of a 1-indexed row, right-trimmed.
func (v *vtScreen) rowText(row int) string {
	v.Lock()
	defer v.Unlock()
	var b strings.Builder
	for x := 0; x < v.cols; x++ {
		g := v.Cell(x, row-1)
		if g.Char == 0 {
			b.WriteRune(' ')
		} else {
			b.WriteRune(g.Char)
		}
	}
	return strings.TrimRight(b.String(), " ")
}

// allBlank returns true when every cell in the inclusive 1-indexed row range
// is empty (null rune or space).
func (v *vtScreen) allBlank(fromRow, toRow int) bool {
	v.Lock()
	defer v.Unlock()
	for r := fromRow - 1; r < toRow; r++ {
		for x := 0; x < v.cols; x++ {
			g := v.Cell(x, r)
			if g.Char != 0 && g.Char != ' ' {
				return false
			}
		}
	}
	return true
}

// ---- helpers ----

func newBar(t *testing.T, cols, rows int) (*statusbar.StatusBar, *bytes.Buffer, *vtScreen) {
	t.Helper()
	var buf bytes.Buffer
	sb := statusbar.New(&buf,
		statusbar.WithText("proxpass", "guest (ct100) @ rome"),
		statusbar.WithHint("Ctrl+A X: disconnect"),
	)
	_ = sb.Setup(cols, rows)
	vt := newVT(cols, rows)
	vt.feed(buf.Bytes())
	buf.Reset()
	return sb, &buf, vt
}

// ---- tests ----

func TestSetupDrawsBarOnLastRow(t *testing.T) {
	cols, rows := 60, 10
	sb, _, vt := newBar(t, cols, rows)
	_ = sb

	bar := vt.rowText(rows)
	if !strings.Contains(bar, "proxpass") {
		t.Errorf("row %d should contain prefix, got: %q", rows, bar)
	}
	if !strings.Contains(bar, "Ctrl+A X") {
		t.Errorf("row %d should contain hint, got: %q", rows, bar)
	}
	if !vt.allBlank(1, rows-1) {
		for r := 1; r < rows; r++ {
			if s := vt.rowText(r); s != "" {
				t.Errorf("row %d should be blank after Setup, got: %q", r, s)
			}
		}
	}
}

func TestWriterPreservesBarAfterClearScreen(t *testing.T) {
	cols, rows := 60, 10
	sb, buf, vt := newBar(t, cols, rows)

	w := sb.Writer()
	_, _ = w.Write([]byte("\x1b[H\x1b[2J"))
	vt.feed(buf.Bytes())

	bar := vt.rowText(rows)
	if !strings.Contains(bar, "proxpass") {
		t.Errorf("bar must survive clear-screen; row %d: %q", rows, bar)
	}
}

func TestWriterPreservesBarAfterAltScreenExit(t *testing.T) {
	cols, rows := 60, 10
	sb, buf, vt := newBar(t, cols, rows)

	w := sb.Writer()
	_, _ = w.Write([]byte("\x1b[?1049l"))
	vt.feed(buf.Bytes())

	bar := vt.rowText(rows)
	if !strings.Contains(bar, "proxpass") {
		t.Errorf("bar must survive alt-screen exit; row %d: %q", rows, bar)
	}
}

func TestWriterPreservesBarAfterAllAltScreenVariants(t *testing.T) {
	cols, rows := 60, 10
	for _, seq := range []string{"\x1b[?1049l", "\x1b[?1047l", "\x1b[?47l"} {
		seq := seq
		t.Run(seq, func(t *testing.T) {
			sb, buf, vt := newBar(t, cols, rows)
			w := sb.Writer()
			_, _ = w.Write([]byte(seq))
			vt.feed(buf.Bytes())
			bar := vt.rowText(rows)
			if !strings.Contains(bar, "proxpass") {
				t.Errorf("bar must survive %q; row %d: %q", seq, rows, bar)
			}
		})
	}
}

func TestWriterClampsGuestDECSTBM(t *testing.T) {
	// Guest tries to expand scroll region to full screen including bar row.
	// Our Writer must clamp it so guest content cannot overwrite the bar.
	cols, rows := 40, 10
	sb, buf, vt := newBar(t, cols, rows)

	w := sb.Writer()
	var fill bytes.Buffer
	// Guest sets full-screen DECSTBM then fills every row
	fill.WriteString("\x1b[1;10r") // would include bar row (row 10)
	for i := 0; i < rows; i++ {
		fill.WriteString("XXXXXXXXXX\r\n")
	}
	_, _ = w.Write(fill.Bytes())
	vt.feed(buf.Bytes())

	bar := vt.rowText(rows)
	if strings.Contains(bar, "XXXXXXXXXX") {
		t.Errorf("guest content leaked into bar row %d: %q", rows, bar)
	}
	if !strings.Contains(bar, "proxpass") {
		t.Errorf("bar content missing from row %d: %q", rows, bar)
	}
}

func TestClearErasesGuestAreaPreservesBar(t *testing.T) {
	cols, rows := 60, 10
	sb, buf, vt := newBar(t, cols, rows)

	// Write content into a guest row via the bar writer.
	w := sb.Writer()
	_, _ = w.Write([]byte("\x1b[1;1HAAAAAAAAAA"))
	vt.feed(buf.Bytes())

	if r := vt.rowText(1); !strings.Contains(r, "A") {
		t.Fatalf("precondition: row 1 should have 'A', got: %q", r)
	}
	buf.Reset()

	// Clear the guest viewport.
	sb.Clear()
	vt.feed(buf.Bytes())

	if !vt.allBlank(1, rows-1) {
		for r := 1; r < rows; r++ {
			if s := vt.rowText(r); s != "" {
				t.Errorf("Clear() should erase row %d, got: %q", r, s)
			}
		}
	}
	bar := vt.rowText(rows)
	if !strings.Contains(bar, "proxpass") {
		t.Errorf("Clear() must not erase bar row %d; got: %q", rows, bar)
	}
}

func TestTeardownClearsBarRow(t *testing.T) {
	cols, rows := 60, 10
	sb, buf, vt := newBar(t, cols, rows)

	sb.Teardown()
	vt.feed(buf.Bytes())

	// After teardown the bar row should be blank.
	bar := vt.rowText(rows)
	if bar != "" {
		t.Errorf("Teardown should clear bar row %d; got: %q", rows, bar)
	}
}

func TestResizeMovesBarToNewLastRow(t *testing.T) {
	cols := 60
	sb, buf, _ := newBar(t, cols, 10)

	// Resize to 20 rows — bar should now be on row 20.
	vtBig := newVT(cols, 20)
	guestH := sb.Resize(cols, 20)
	vtBig.feed(buf.Bytes())

	if guestH != 19 {
		t.Errorf("Resize guest height = %d, want 19", guestH)
	}
	bar := vtBig.rowText(20)
	if !strings.Contains(bar, "proxpass") {
		t.Errorf("after Resize bar should be on row 20, got: %q", bar)
	}
	// Old bar row (10) should not have bar content on the bigger terminal.
	oldBar := vtBig.rowText(10)
	if strings.Contains(oldBar, "Ctrl+A X") {
		t.Errorf("old row 10 should not have bar after resize, got: %q", oldBar)
	}
}

func TestGuestContentStaysInScrollRegion(t *testing.T) {
	// The guest should not be able to write into the bar row via normal scrolling.
	cols, rows := 40, 6
	sb, buf, vt := newBar(t, cols, rows)
	// guestRows = 5, bar at row 6

	w := sb.Writer()
	// Fill 10 lines — with scroll region 1..5, content should scroll within
	// rows 1-5 and never touch row 6.
	var fill bytes.Buffer
	fill.WriteString("\x1b[1;1H") // home
	for i := 0; i < 10; i++ {
		fill.WriteString("LINE\r\n")
	}
	_, _ = w.Write(fill.Bytes())
	vt.feed(buf.Bytes())

	bar := vt.rowText(rows)
	if !strings.Contains(bar, "proxpass") {
		t.Errorf("bar row %d should still have bar content, got: %q", rows, bar)
	}
}
