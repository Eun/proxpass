package ssh

import (
	"bytes"
	"testing"
)

const crlfHelloWorld = "hello\r\nworld\r\n"

func TestCRLFWriter(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wanted string
	}{
		{
			name:   "bare newline converted",
			input:  "hello\nworld\n",
			wanted: crlfHelloWorld,
		},
		{
			name:   "already crlf untouched",
			input:  crlfHelloWorld,
			wanted: crlfHelloWorld,
		},
		{
			name:   "no newline",
			input:  "hello world",
			wanted: "hello world",
		},
		{
			name:   "leading newline",
			input:  "\nfoo",
			wanted: "\r\nfoo",
		},
		{
			name:   "multiple consecutive newlines",
			input:  "a\n\nb",
			wanted: "a\r\n\r\nb",
		},
		{
			name:   "mixed",
			input:  "a\r\nb\nc",
			wanted: "a\r\nb\r\nc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := newCRLFWriter(&buf)
			n, err := w.Write([]byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// n should equal the length of the original input
			if n != len(tt.input) {
				t.Errorf("wrote %d bytes, want %d", n, len(tt.input))
			}
			if got := buf.String(); got != tt.wanted {
				t.Errorf("buf = %q, want %q", got, tt.wanted)
			}
		})
	}
}
