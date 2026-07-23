package ssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
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
	// Connect via the Proxmox API vncwebsocket endpoint (same host:port as
	// --api-url). The termproxy binary listens only on localhost of the
	// Proxmox node; the API endpoint proxies to it.
	// Auth: PVEAPIToken in the Authorization header.
	dialOpts := &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{
				fmt.Sprintf("PVEAPIToken=%s=%s", inst.APITokenID, inst.APITokenSecret),
			},
		},
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
	// Proxmox sends "OK" once the ticket and auth check pass. If it closes
	// immediately (EOF), it rejected verify_vnc_ticket. Log the close code.
	_, handshake, err := conn.Read(ctx)
	if err != nil {
		var closeErr websocket.CloseError
		if errors.As(err, &closeErr) {
			logger.Printf("termproxy: server closed (code=%d reason=%q url=%s)",
				closeErr.Code, closeErr.Reason, wsURL)
			return fmt.Errorf("termproxy server closed connection: code=%d reason=%q",
				closeErr.Code, closeErr.Reason)
		}
		logger.Printf("termproxy: handshake failed (url=%s): %v", wsURL, err)
		return fmt.Errorf("read termproxy handshake: %w", err)
	}
	if string(handshake) != "OK" {
		return fmt.Errorf("unexpected termproxy handshake: %q", handshake)
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

// buildVNCWebSocketURL constructs the WebSocket URL for the Proxmox
// vncwebsocket endpoint. The WebSocket connects to the same host:port as the
// API URL (e.g. rome:8006); the Proxmox API proxies the connection through to
// the termproxy binary listening on localhost.
// ticket.Port and ticket.Ticket are passed as query parameters so the
// Proxmox API can locate and authenticate the termproxy session.
func buildVNCWebSocketURL(apiURL *url.URL, node, kind string, vmid int, ticket *proxmox.TermProxyTicket) string {
	wsScheme := "ws"
	if apiURL.Scheme == "https" {
		wsScheme = "wss"
	}

	path := fmt.Sprintf("/api2/json/nodes/%s/%s/%d/vncwebsocket", node, kind, vmid)

	// Build RawQuery manually so url.Values.Encode() encodes the ticket once;
	// url.URL.String() then emits RawQuery verbatim — no double-encoding.
	q := url.Values{}
	q.Set("port", fmt.Sprintf("%d", ticket.Port))
	q.Set("vncticket", ticket.Ticket)

	u := &url.URL{
		Scheme:   wsScheme,
		Host:     apiURL.Host, // same host:port as --api-url (e.g. rome:8006)
		Path:     path,
		RawQuery: q.Encode(),
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
