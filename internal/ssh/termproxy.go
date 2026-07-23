package ssh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"sync"

	"proxpass/internal/models"
	"proxpass/internal/proxmox"

	"github.com/coder/websocket"
	gossh "golang.org/x/crypto/ssh"
)

// proxyViaTermProxy establishes a Proxmox termproxy WebSocket session and
// bridges it bidirectionally to the SSH client channel.
//
// Protocol:
//  1. POST /api2/json/nodes/{node}/{lxc|qemu}/{vmid}/termproxy  → ticket + port
//  2. Dial wss://{apiHost}:{port}/api2/json/nodes/{node}/.../vncwebsocket
//     ?port=<port>&vncticket=<url-encoded-ticket>
//  3. Read first binary frame — must be exactly "OK"
//  4. If PTY: send initial resize JSON text frame
//  5. Bidirectional copy until either side closes
//
//nolint:gocognit // termproxy bridging requires sequential setup of goroutines and teardown
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
	logger.Printf("termproxy: ticket obtained (port=%d user=%q ticket-prefix=%q)",
		ticket.Port, ticket.User, truncateTicket(ticket.Ticket))

	// --- Step 2: Build WebSocket URL ---
	// The WebSocket connects to the same host as the API but on the port
	// returned by the termproxy endpoint.
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

	// --- Step 3: Dial WebSocket ---
	// Connect directly to the termproxy binary (ws://host:port/).
	// The termproxy binary validates the VNC ticket passed as the
	// Sec-WebSocket-Protocol subprotocol header.
	dialOpts := &websocket.DialOptions{
		Subprotocols: []string{ticket.Ticket},
		// No TLS: the termproxy binary does not do TLS itself.
		HTTPClient: proxmox.InsecureHTTPClient(),
	}

	conn, wsResp, err := websocket.Dial(ctx, wsURL, dialOpts)
	if wsResp != nil && wsResp.Body != nil {
		_ = wsResp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("dial termproxy websocket %s: %w", wsURL, err)
	}
	defer func() { _ = conn.CloseNow() }()

	// --- Step 4: Read handshake frame "OK" ---
	// termproxy sends "OK" immediately after the WebSocket upgrade.
	// Proxmox closes the connection (EOF) without sending "OK" when the
	// vncticket validation fails. Log enough context to diagnose.
	// Any bytes after "OK" in the same frame are the start of the terminal stream.
	_, firstMsg, err := conn.Read(ctx)
	if err != nil {
		logger.Printf("termproxy: handshake EOF for url=%s node=%s vmid=%d",
			wsURL, inst.Node, guest.ProxmoxID)
		return fmt.Errorf("read termproxy handshake: %w", err)
	}
	if len(firstMsg) < 2 || firstMsg[0] != 'O' || firstMsg[1] != 'K' {
		return fmt.Errorf("unexpected termproxy handshake: %q", firstMsg)
	}
	// Forward any terminal data that arrived in the same frame as "OK".
	if len(firstMsg) > 2 {
		if _, err := clientChan.Write(firstMsg[2:]); err != nil {
			return fmt.Errorf("write initial terminal data: %w", err)
		}
	}

	// --- Step 5: Send initial resize frame if PTY was requested ---
	if ptyReq != nil {
		if err := sendResizeFrame(ctx, conn, ptyReq.Width, ptyReq.Height); err != nil {
			return fmt.Errorf("send initial resize: %w", err)
		}
	}

	// --- Step 6: Bidirectional copy ---
	// done signals the request-forwarding goroutine to stop once the
	// WebSocket reader exits (either side closed).
	done := make(chan struct{})
	var wg sync.WaitGroup

	// Forward window-change SSH requests as WebSocket resize frames.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			case req, ok := <-clientReqs:
				if !ok {
					return
				}
				switch req.Type {
				case "window-change":
					w, h, parseErr := parseWindowChange(req.Payload)
					if parseErr == nil {
						_ = sendResizeFrame(ctx, conn, w, h)
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

	// SSH client → WebSocket. Not in WaitGroup; closes conn when client
	// closes so the WebSocket reader goroutine exits naturally.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := clientChan.Read(buf)
			if n > 0 {
				if writeErr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); writeErr != nil {
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

	// WebSocket → SSH client. Controls overall lifetime: when this exits,
	// we signal done and tear down.
	wsReaderDone := make(chan struct{})
	go func() {
		defer close(wsReaderDone)
		for {
			_, data, readErr := conn.Read(ctx)
			if readErr != nil {
				return
			}
			if _, writeErr := clientChan.Write(data); writeErr != nil {
				return
			}
		}
	}()

	<-wsReaderDone
	close(done)
	wg.Wait()
	return nil
}

// truncateTicket returns the first 20 bytes of a ticket value followed by "...",
// so debug logs are informative without leaking the full credential.
func truncateTicket(s string) string {
	const n = 20
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// buildVNCWebSocketURL constructs the WebSocket URL to connect directly
// to the termproxy binary, which listens on the port returned by the termproxy
// POST endpoint.
//
// The termproxy binary is a standalone WebSocket server; it does NOT go through
// the Proxmox API (port 8006). Connect to host:ticketPort directly.
// The ticket is sent as the WebSocket subprotocol so the termproxy binary can
// validate it.
func buildVNCWebSocketURL(apiURL *url.URL, node, kind string, vmid int, ticket *proxmox.TermProxyTicket) string {
	// The termproxy binary listens on a plain (non-TLS) TCP port on the Proxmox host.
	// Always use "ws" (not "wss") since the termproxy binary itself does not do TLS;
	// TLS termination happens at the Proxmox API layer.
	_ = node
	_ = kind
	_ = vmid

	u := &url.URL{
		Scheme: "ws",
		Host:   fmt.Sprintf("%s:%d", apiURL.Hostname(), ticket.Port),
		Path:   "/",
	}
	return u.String()
}

// sendResizeFrame sends a Proxmox termproxy resize frame as a JSON text message.
// Format: {"resize":{"width":N,"height":M}}.
func sendResizeFrame(ctx context.Context, conn *websocket.Conn, width, height uint32) error {
	type resizeInner struct {
		Width  uint32 `json:"width"`
		Height uint32 `json:"height"`
	}
	type resizePayload struct {
		Resize resizeInner `json:"resize"`
	}
	payload := resizePayload{Resize: resizeInner{Width: width, Height: height}}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, data)
}
