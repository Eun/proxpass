package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"proxpass/internal/models"
	"proxpass/internal/proxmox"

	"github.com/coder/websocket"
	gossh "golang.org/x/crypto/ssh"
)

// proxyViaTermProxy establishes a Proxmox termproxy WebSocket session and
// bridges it bidirectionally to the SSH client channel.
//
// Protocol — derived from the proxmox-termproxy Rust source (pve-xtermjs repo)
// and the luthermonson/go-proxmox reference implementation:
//
//  1. POST .../termproxy with PVEAPIToken → {ticket, port, user}
//  2. Dial wss://.../vncwebsocket?port=N&vncticket=T
//     Sec-WebSocket-Protocol: binary
//     Authorization: PVEAPIToken=...
//     The Proxmox API proxies this WebSocket transparently to the termproxy
//     binary listening on localhost:port.
//  3. Send auth line as a single binary WebSocket frame: "<authid>:<ticket>\n"
//     termproxy reads this, validates it via POST /api2/json/access/vncticket
//     (PVE 9 --vncticket-endpoint), then writes exactly "OK" back.
//  4. Read the "OK" frame. Any bytes beyond "OK" in the same frame are the
//     start of terminal output and must be forwarded immediately.
//  5. Send initial resize: "1:<cols>:<rows>:" as a binary frame.
//  6. Bidirectional bridge:
//     - Input (SSH → WS): "0:<len>:<data>" — len is ASCII decimal, data is
//     raw bytes appended separately (not via %s which would corrupt binary).
//     - Output (WS → SSH): raw PTY bytes, no framing; forward as-is.
//     - Resize (SSH window-change → WS): "1:<cols>:<rows>:"
//     - Keepalive: send "2" every 30 s to prevent idle disconnection.
//
// Requires PVE 9 with pve-manager >= 9.0.13 and proxmox-termproxy >= 1.1.0
// (--vncticket-endpoint flag). PVE 8 rejects API token IDs as usernames.
//
//nolint:gocognit,gocyclo,funlen // sequential protocol steps + teardown require length
func proxyViaTermProxy(
	clientChan gossh.Channel,
	clientReqs <-chan *gossh.Request,
	guest *models.Guest,
	inst *models.ProxmoxInstance,
	ptyReq *PtyRequest,
	logger *log.Logger,
) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Step 1: Create termproxy ticket via REST API ---
	apiClient, err := proxmox.NewAPIClient(inst)
	if err != nil {
		return fmt.Errorf("build api client: %w", err)
	}

	ticket, err := apiClient.CreateTermProxyTicket(ctx, inst.Node, guest)
	if err != nil {
		return fmt.Errorf("create termproxy ticket: %w", err)
	}
	logger.Printf("termproxy: ticket obtained (port=%d user=%q)", ticket.Port, ticket.User)

	// --- Step 2: Build vncwebsocket URL ---
	apiURL, err := url.Parse(inst.APIURL)
	if err != nil {
		return fmt.Errorf("parse api url: %w", err)
	}

	var kind string
	switch guest.Type {
	case models.GuestTypeCT:
		kind = "lxc"
	case models.GuestTypeVM:
		kind = "qemu"
	default:
		return fmt.Errorf("unknown guest type %q", guest.Type)
	}

	wsURL := buildVNCWebSocketURL(apiURL, inst.Node, kind, guest.ProxmoxID, ticket)
	logger.Printf("termproxy: dialing %s", wsURL)

	// --- Step 3: Dial WebSocket ---
	// The Proxmox vncwebsocket endpoint requires the "binary" subprotocol and
	// accepts API token auth via Authorization header (pve-manager >= 9.0.13).
	wsHeader := http.Header{
		"Authorization": []string{fmt.Sprintf("PVEAPIToken=%s=%s", inst.APITokenID, inst.APITokenSecret)},
	}
	dialOpts := &websocket.DialOptions{
		Subprotocols: []string{"binary"},
		HTTPHeader:   wsHeader,
		HTTPClient:   proxmox.InsecureHTTPClient(),
	}

	conn, wsResp, err := websocket.Dial(ctx, wsURL, dialOpts)
	if wsResp != nil && wsResp.Body != nil {
		body, _ := io.ReadAll(wsResp.Body)
		_ = wsResp.Body.Close()
		if len(body) > 0 {
			logger.Printf("termproxy: ws dial response body: %q", body)
		}
	}
	if err != nil {
		return fmt.Errorf("dial termproxy websocket %s: %w", wsURL, err)
	}
	defer func() { _ = conn.CloseNow() }()

	// --- Step 4: Authenticate — send "<authid>:<ticket>\n" ---
	// termproxy reads the first '\n'-terminated line, splits on ':', and
	// validates the ticket via POST /api2/json/access/vncticket. On success
	// it writes exactly the two bytes "OK" back.
	authLine := fmt.Sprintf("%s:%s\n", inst.APITokenID, ticket.Ticket)
	if err := conn.Write(ctx, websocket.MessageBinary, []byte(authLine)); err != nil {
		return fmt.Errorf("send auth line: %w", err)
	}

	// --- Step 5: Read "OK" handshake ---
	// The termproxy Rust source writes exactly b"OK" — two bytes, no newline.
	// Any bytes past index 1 in the same frame are early terminal output.
	_, handshake, err := conn.Read(ctx)
	if err != nil {
		var closeErr websocket.CloseError
		if errors.As(err, &closeErr) {
			return fmt.Errorf("termproxy closed during handshake: code=%d reason=%q",
				closeErr.Code, closeErr.Reason)
		}
		return fmt.Errorf("read termproxy handshake: %w", err)
	}
	if len(handshake) < 2 || handshake[0] != 'O' || handshake[1] != 'K' {
		return fmt.Errorf("unexpected termproxy handshake response: %q", handshake)
	}
	if len(handshake) > 2 {
		// Early terminal output arrived in the same frame as "OK".
		if _, err := clientChan.Write(handshake[2:]); err != nil {
			return fmt.Errorf("write initial terminal data: %w", err)
		}
	}

	// --- Step 6: Send initial terminal size ---
	// Format: "1:<cols>:<rows>:" — derived from termproxy Rust source
	// (MSG_TYPE_RESIZE = 1, remove_number reads cols then rows).
	if ptyReq != nil {
		resizeMsg := fmt.Sprintf("1:%d:%d:", ptyReq.Width, ptyReq.Height)
		if err := conn.Write(ctx, websocket.MessageBinary, []byte(resizeMsg)); err != nil {
			return fmt.Errorf("send initial resize: %w", err)
		}
	}

	// --- Step 7: Bidirectional bridge ---
	done := make(chan struct{})

	// SSH channel requests → WebSocket control messages.
	// Handles window-change (resize) and discards everything else.
	// Runs until done is closed (triggered when the WS reader exits).
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// Keepalive ping — MSG_TYPE_PING = 2.
				// Prevents the termproxy binary from closing idle connections.
				_ = conn.Write(ctx, websocket.MessageBinary, []byte("2"))
			case req, ok := <-clientReqs:
				if !ok {
					return
				}
				switch req.Type {
				case "window-change":
					// Format: "1:<cols>:<rows>:" matching termproxy MSG_TYPE_RESIZE.
					w, h, parseErr := parseWindowChange(req.Payload)
					if parseErr == nil {
						msg := fmt.Sprintf("1:%d:%d:", w, h)
						_ = conn.Write(ctx, websocket.MessageBinary, []byte(msg))
					}
					if req.WantReply {
						_ = req.Reply(parseErr == nil, nil)
					}
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}
	}()

	// SSH client → WebSocket: "0:<len>:<data>" binary frames.
	// MSG_TYPE_DATA = 0. Build header and data separately to avoid %s
	// converting the byte slice through a UTF-8 string, which would corrupt
	// non-ASCII bytes (arrow keys, escape sequences) and invalidate the
	// declared length for multi-byte input.
	// Mirrors the approach in luthermonson/go-proxmox TermWebSocket.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, readErr := clientChan.Read(buf)
			if n > 0 {
				header := fmt.Sprintf("0:%d:", n)
				msg := append([]byte(header), buf[:n]...)
				if writeErr := conn.Write(ctx, websocket.MessageBinary, msg); writeErr != nil {
					return
				}
			}
			if readErr != nil {
				if readErr != io.EOF {
					logger.Printf("termproxy: client read error: %v", readErr)
				}
				_ = conn.Close(websocket.StatusNormalClosure, "")
				return
			}
		}
	}()

	// WebSocket → SSH client: raw PTY output, no framing.
	// The termproxy binary writes PTY bytes directly to the TCP socket;
	// the vncwebsocket tunnel forwards them verbatim as binary WS frames.
	// When the WS reader exits (connection closed by either side), signal
	// done to stop the control goroutine.
	for {
		_, data, readErr := conn.Read(ctx)
		if readErr != nil {
			break
		}
		if _, writeErr := clientChan.Write(data); writeErr != nil {
			break
		}
	}
	close(done)
	return nil
}

// buildVNCWebSocketURL constructs the WebSocket URL for the Proxmox
// vncwebsocket endpoint. The WebSocket connects to the same host:port as
// the API URL (e.g. rome:8006); the Proxmox API proxies the connection
// through to the termproxy binary listening on localhost.
func buildVNCWebSocketURL(apiURL *url.URL, node, kind string, vmid int, ticket *proxmox.TermProxyTicket) string {
	wsScheme := "ws"
	if apiURL.Scheme == "https" {
		wsScheme = "wss"
	}

	path := fmt.Sprintf("/api2/json/nodes/%s/%s/%d/vncwebsocket", node, kind, vmid)

	q := url.Values{}
	q.Set("port", fmt.Sprintf("%d", ticket.Port))
	q.Set("vncticket", ticket.Ticket)

	u := &url.URL{
		Scheme:   wsScheme,
		Host:     apiURL.Host,
		Path:     path,
		RawQuery: q.Encode(),
	}
	return u.String()
}
