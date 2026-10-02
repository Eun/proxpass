package console

import (
	"bytes"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// splitWriter is a terminal that writes one byte at a time, recording the
// order bytes arrive in from every goroutine.
//
// A PTY write is not atomic: os.File.Write loops on a short write. A writer
// that is not serialized can therefore be cut in half by another goroutine's
// write, which no test using an ordinary buffer can reproduce -- a single
// bytes.Buffer.Write appends its whole slice before yielding. This one yields
// between every byte, so an unsynchronized writer is guaranteed to interleave
// rather than merely able to.
type splitWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *splitWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		w.mu.Lock()
		w.buf.WriteByte(b)
		w.mu.Unlock()
		// Yield, so a concurrent writer gets the chance to interleave.
		runtime.Gosched()
	}
	return len(p), nil
}

func (w *splitWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// The bar and the guest share one terminal. Neither may be spliced into the
// middle of the other's escape sequences: a repaint landing inside a guest
// sequence corrupts it, and guest bytes landing between the bar's cursor save
// and restore make the restore discard the guest's position -- the same class
// of cursor bug as the save-slot collision, by a different route.
//
// b.mu does not cover this. It guards the bar's state, and barWriter used to
// forward guest output before taking it, with the terminal written outside
// the lock entirely.
func TestBarAndGuestWritesAreNotInterleaved(t *testing.T) {
	term := &splitWriter{}
	bar := NewStatusBar(term, barCols, barRows)
	bar.SetText("webserver (ct100) @ pve1", EscapeHint)
	bar.active = true

	guest := &barWriter{bar: bar}

	// A guest sequence that must survive intact. Any bar byte inside it
	// would corrupt it.
	const payload = "\x1b[1;2;3;4;5;6;7;8;9mGUESTPAYLOAD\x1b[0m"

	var wg sync.WaitGroup
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = guest.Write([]byte(payload))
		}()
	}
	for i := range 40 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Vary the text so the unchanged-repaint skip does not suppress
			// the draws this test depends on.
			bar.SetText(strings.Repeat("x", i%7+1), EscapeHint)
			bar.draw()
		}(i)
	}
	wg.Wait()

	got := term.String()

	// Every guest payload must appear unbroken. Counting occurrences is the
	// assertion: if a bar repaint was spliced into one, that copy no longer
	// matches and the count drops.
	if n := strings.Count(got, payload); n != 40 {
		t.Errorf("found %d intact guest payloads, want 40: a bar repaint was "+
			"interleaved into a guest escape sequence", n)
	}

	// And symmetrically, the bar's save/restore must never enclose guest
	// bytes. Each repaint is DECSC ... DECRC with nothing of the guest's
	// inside it.
	for _, chunk := range strings.Split(got, "\x1b7")[1:] {
		end := strings.Index(chunk, "\x1b8")
		if end < 0 {
			continue // a repaint still in flight at the end of the capture
		}
		if strings.Contains(chunk[:end], "GUESTPAYLOAD") {
			t.Error("guest output landed between the bar's cursor save and " +
				"restore, so the restore discarded the guest's position")
			break
		}
	}
}
