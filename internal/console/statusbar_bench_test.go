package console

import (
	"io"
	"strings"
	"testing"
)

// The point of this design is that the cost of a status bar does not scale
// with how much the guest prints. These benchmarks measure the per-write
// overhead the bar adds to a guest's output stream.
//
// The previous implementation fed every write through a VT100 emulator and
// re-rendered the whole cell grid, which is O(cols x rows) per write and is
// why PROXPASS_DISABLE_STATUSBAR had to exist (#37). Here the work per write
// is a scan for escape sequences, with drawing decoupled onto a timer, so
// these numbers should stay flat as the payload grows.

// barWriteBench runs payload through the bar's observer.
func barWriteBench(b *testing.B, payload []byte) {
	b.Helper()
	bar := NewStatusBar(io.Discard, 80, 24)
	bar.SetText("guest (ct100) @ pve", EscapeHint)
	bar.Start()
	defer bar.Stop()

	w := &barWriter{bar: bar}
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		_, _ = w.Write(payload)
	}
}

// A typical line of log output.
func BenchmarkBarWriteLogLine(b *testing.B) {
	barWriteBench(b, []byte("2026-10-01T12:00:00Z INFO  something happened id=12345\n"))
}

// A 4 KiB chunk, the size a copy loop actually moves when a guest is
// producing output continuously.
func BenchmarkBarWriteChunk4K(b *testing.B) {
	barWriteBench(b, []byte(strings.Repeat("x", 4096)))
}

// Colored output, so the scan has escape sequences to step over.
func BenchmarkBarWriteColored(b *testing.B) {
	barWriteBench(b, []byte(strings.Repeat("\x1b[31mred\x1b[0m plain ", 100)))
}

// The baseline: the same writes with no bar at all. The gap between this and
// the benchmarks above is the whole cost of having a status bar.
func BenchmarkNoBarWriteChunk4K(b *testing.B) {
	payload := []byte(strings.Repeat("x", 4096))
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		_, _ = io.Discard.Write(payload)
	}
}

// Laying out the bar text is the only per-draw work, and draws are throttled
// and skipped when unchanged, so this runs far less often than once per
// write.
func BenchmarkBarTextLayout(b *testing.B) {
	for range b.N {
		_ = barText("guest (ct100) @ pve", EscapeHint, 80)
	}
}
