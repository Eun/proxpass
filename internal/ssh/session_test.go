package ssh

import (
	"encoding/binary"
	"testing"
)

// buildPtyReqPayload constructs an RFC 4254 §6.2 pty-req payload.
func buildPtyReqPayload(term string, width, height, pixW, pixH uint32, modes []byte) []byte {
	// string term: uint32 len + bytes
	termBytes := []byte(term)
	// string modes: uint32 len + bytes
	buf := make([]byte, 0, 4+len(termBytes)+16+4+len(modes))

	b4 := make([]byte, 4)

	// term length + term
	binary.BigEndian.PutUint32(b4, uint32(len(termBytes))) //nolint:gosec // test data, length is controlled
	buf = append(buf, b4...)
	buf = append(buf, termBytes...)

	// width
	binary.BigEndian.PutUint32(b4, width)
	buf = append(buf, b4...)
	// height
	binary.BigEndian.PutUint32(b4, height)
	buf = append(buf, b4...)
	// pixel width
	binary.BigEndian.PutUint32(b4, pixW)
	buf = append(buf, b4...)
	// pixel height
	binary.BigEndian.PutUint32(b4, pixH)
	buf = append(buf, b4...)

	// modes length + modes
	binary.BigEndian.PutUint32(b4, uint32(len(modes))) //nolint:gosec // test data, length is controlled
	buf = append(buf, b4...)
	buf = append(buf, modes...)

	return buf
}

// buildWindowChangePayload constructs an RFC 4254 §6.7 window-change payload.
func buildWindowChangePayload(cols, rows, pixW, pixH uint32) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint32(buf[0:4], cols)
	binary.BigEndian.PutUint32(buf[4:8], rows)
	binary.BigEndian.PutUint32(buf[8:12], pixW)
	binary.BigEndian.PutUint32(buf[12:16], pixH)
	return buf
}

func TestParsePtyReq(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantTerm   string
		wantWidth  uint32
		wantHeight uint32
		wantErr    bool
	}{
		{
			name:       "valid xterm-256color",
			data:       buildPtyReqPayload("xterm-256color", 120, 40, 0, 0, []byte{0}),
			wantTerm:   "xterm-256color",
			wantWidth:  120,
			wantHeight: 40,
		},
		{
			name:       "valid vt100 with modes",
			data:       buildPtyReqPayload("vt100", 80, 24, 640, 480, []byte{53, 0, 0, 0, 1, 0}),
			wantTerm:   "vt100",
			wantWidth:  80,
			wantHeight: 24,
		},
		{
			name:       "empty term string",
			data:       buildPtyReqPayload("", 80, 24, 0, 0, nil),
			wantTerm:   "",
			wantWidth:  80,
			wantHeight: 24,
		},
		{
			name:       "no modes section",
			data:       buildPtyReqPayload(termXterm, 100, 50, 0, 0, nil),
			wantTerm:   termXterm,
			wantWidth:  100,
			wantHeight: 50,
		},
		{
			name:    "empty payload",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "too short - only 3 bytes",
			data:    []byte{0, 0, 1},
			wantErr: true,
		},
		{
			name: "term length exceeds payload",
			data: func() []byte {
				b := make([]byte, 4)
				binary.BigEndian.PutUint32(b, 999) // claim 999-byte term
				return b
			}(),
			wantErr: true,
		},
		{
			name: "missing dimension fields after term",
			data: func() []byte {
				// term = "hi" (2 bytes) but only 4 bytes after for dimensions (need 16)
				buf := make([]byte, 4+2+4)
				binary.BigEndian.PutUint32(buf[0:4], 2)
				copy(buf[4:6], "hi")
				return buf
			}(),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePtyReq(tc.data)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Term != tc.wantTerm {
				t.Errorf("Term = %q, want %q", got.Term, tc.wantTerm)
			}
			if got.Width != tc.wantWidth {
				t.Errorf("Width = %d, want %d", got.Width, tc.wantWidth)
			}
			if got.Height != tc.wantHeight {
				t.Errorf("Height = %d, want %d", got.Height, tc.wantHeight)
			}
		})
	}
}

func TestParseWindowChange(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantWidth  uint32
		wantHeight uint32
		wantErr    bool
	}{
		{
			name:       "valid 120x40",
			data:       buildWindowChangePayload(120, 40, 0, 0),
			wantWidth:  120,
			wantHeight: 40,
		},
		{
			name:       "valid 80x24 with pixel dims",
			data:       buildWindowChangePayload(80, 24, 640, 480),
			wantWidth:  80,
			wantHeight: 24,
		},
		{
			name:       "minimum valid payload (exactly 8 bytes)",
			data:       buildWindowChangePayload(1, 1, 0, 0)[:8],
			wantWidth:  1,
			wantHeight: 1,
		},
		{
			name:    "empty payload",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "7 bytes - one short",
			data:    make([]byte, 7),
			wantErr: true,
		},
		{
			name:    "4 bytes - only cols",
			data:    make([]byte, 4),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, h, err := parseWindowChange(tc.data)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if w != tc.wantWidth {
				t.Errorf("width = %d, want %d", w, tc.wantWidth)
			}
			if h != tc.wantHeight {
				t.Errorf("height = %d, want %d", h, tc.wantHeight)
			}
		})
	}
}
