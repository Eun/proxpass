package testenv

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/coder/websocket"
)

// TermProxyTranscript records what a mock termproxy session observed, so
// tests can assert on the protocol rather than only on the output.
type TermProxyTranscript struct {
	mu        sync.Mutex
	authLine  string
	input     []byte
	resizes   [][2]int
	pings     int
	connected bool
}

// AuthLine returns the "<authid>:<ticket>" line the client sent first.
func (t *TermProxyTranscript) AuthLine() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.authLine
}

// Input returns every data byte the client sent after authenticating.
func (t *TermProxyTranscript) Input() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.input)
}

// Resizes returns the (cols, rows) pairs the client requested.
func (t *TermProxyTranscript) Resizes() [][2]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([][2]int, len(t.resizes))
	copy(out, t.resizes)
	return out
}

// Connected reports whether a client completed the handshake.
func (t *TermProxyTranscript) Connected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}

// TermProxy returns the transcript for the most recent websocket session.
func (m *MockAPIServer) TermProxy() *TermProxyTranscript {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.termProxy == nil {
		return &TermProxyTranscript{}
	}
	return m.termProxy
}

// SetTermProxyGreeting sets the bytes the mock writes to the client once the
// handshake completes, standing in for the guest's first console output.
func (m *MockAPIServer) SetTermProxyGreeting(greeting string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.termProxyGreeting = greeting
}

// handleVNCWebSocket implements enough of the Proxmox vncwebsocket +
// proxmox-termproxy protocol to exercise the client:
//
//	client → "<authid>:<ticket>\n"   (first line)
//	server → "OK"                    (exactly two bytes)
//	client → "0:<len>:<data>"        (input)
//	client → "1:<cols>:<rows>:"      (resize)
//	client → "2"                     (keepalive ping)
//	server → raw PTY bytes           (unframed)
func (m *MockAPIServer) handleVNCWebSocket(w http.ResponseWriter, r *http.Request) {
	transcript := &TermProxyTranscript{}
	m.mu.Lock()
	m.termProxy = transcript
	greeting := m.termProxyGreeting
	m.mu.Unlock()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"binary"},
	})
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()

	ctx := r.Context()

	// The first frame carries the authentication line.
	_, first, err := conn.Read(ctx)
	if err != nil {
		return
	}
	line := string(first)
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	transcript.mu.Lock()
	transcript.authLine = line
	transcript.connected = true
	transcript.mu.Unlock()

	// termproxy answers with exactly "OK".
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("OK")); err != nil {
		return
	}
	if greeting != "" {
		if err := conn.Write(ctx, websocket.MessageBinary, []byte(greeting)); err != nil {
			return
		}
	}

	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			return
		}
		m.handleTermProxyFrame(ctx, conn, transcript, msg)
	}
}

// handleTermProxyFrame decodes one client frame and echoes data back, which
// is what lets a test observe that input reached the "guest".
func (m *MockAPIServer) handleTermProxyFrame(
	ctx context.Context,
	conn *websocket.Conn,
	transcript *TermProxyTranscript,
	msg []byte,
) {
	if len(msg) == 0 {
		return
	}
	switch msg[0] {
	case '2': // keepalive
		transcript.mu.Lock()
		transcript.pings++
		transcript.mu.Unlock()

	case '0': // data: "0:<len>:<payload>"
		rest := msg[2:] // skip "0:"
		idx := strings.IndexByte(string(rest), ':')
		if idx < 0 {
			return
		}
		n, err := strconv.Atoi(string(rest[:idx]))
		if err != nil {
			return
		}
		payload := rest[idx+1:]
		if n > len(payload) {
			n = len(payload)
		}
		transcript.mu.Lock()
		transcript.input = append(transcript.input, payload[:n]...)
		transcript.mu.Unlock()
		// Echo unframed, exactly as the real PTY does.
		_ = conn.Write(ctx, websocket.MessageBinary, payload[:n])

	case '1': // resize: "1:<cols>:<rows>:"
		fields := strings.Split(string(msg), ":")
		if len(fields) < 3 {
			return
		}
		cols, err1 := strconv.Atoi(fields[1])
		rows, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return
		}
		transcript.mu.Lock()
		transcript.resizes = append(transcript.resizes, [2]int{cols, rows})
		transcript.mu.Unlock()
		_ = conn.Write(ctx, websocket.MessageBinary,
			[]byte(fmt.Sprintf("[resized %dx%d]", cols, rows)))
	}
}
