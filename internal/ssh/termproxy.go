package ssh

import (
	"context"
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
// Protocol (from Proxmox xtermjs/main.js):
//  1. GET session ticket: POST /access/ticket → PVEAuthCookie value
//  2. POST .../termproxy with PVEAuthCookie → VNC ticket + port
//  3. Dial wss://.../vncwebsocket?port=N&vncticket=T
//     Sec-WebSocket-Protocol: binary
//     Cookie: PVEAuthCookie=<session ticket>
//  4. First message from server starts with "OK" (bytes 79,75); remainder is terminal data
//  5. After "OK": send "<username>:<vncticket>\n"
//  6. Terminal input:  send "0:<len>:<data>"
//     Terminal resize: send "1:<cols>:<rows>:"
//     Keepalive ping:  send "2"
//  7. Server sends raw terminal bytes (binary frames)
//
//nolint:gocognit,gocyclo,funlen // termproxy bridging requires sequential setup and teardown
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

	// --- Step 1: Obtain auth credentials for termproxy ---
	// Older Proxmox versions (termproxy without --vncticket-endpoint) verify
	// the auth line via POST /access/ticket which requires a real user identity
	// (e.g. root@pam), not an API token identity (root@pam!token).
	// When inst.Username/Password are set, we use a session ticket for both
	// the termproxy POST and the vncwebsocket — this produces a VNC ticket
	// assembled with the user identity, matching what termproxy expects.
	// When not set, API token auth is used (works with newer Proxmox +
	// --vncticket-endpoint).
	apiClient, err := proxmox.NewAPIClient(inst)
	if err != nil {
		return fmt.Errorf("build api client: %w", err)
	}

	var ticket *proxmox.TermProxyTicket
	var session *proxmox.SessionTicket

	if inst.Username != "" {
		// Session ticket auth: get a user session ticket, use it for both
		// the termproxy POST and the vncwebsocket Cookie.
		session, err = apiClient.GetSessionTicket(ctx, inst.Username, inst.Password)
		if err != nil {
			return fmt.Errorf("get session ticket: %w", err)
		}
		ticket, err = apiClient.CreateTermProxyTicketWithSession(ctx, inst.Node, guest, session)
	} else {
		// API token auth: both termproxy POST and vncwebsocket use the token.
		// The VNC ticket is assembled with the token identity; the authid in
		// the termproxy auth line must match (inst.APITokenID).
		ticket, err = apiClient.CreateTermProxyTicket(ctx, inst.Node, guest)
	}
	if err != nil {
		return fmt.Errorf("create termproxy ticket: %w", err)
	}

	// --- Step 3: Build WebSocket URL ---
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

	// --- Step 4: Dial WebSocket ---
	// Subprotocol: "binary" (required by Proxmox vncwebsocket).
	// Auth: use the same credentials as the termproxy POST so that the
	// vncwebsocket verify_vnc_ticket check sees the same identity.
	var wsHeader http.Header
	if session != nil {
		wsHeader = http.Header{
			// Cookie value must be the raw ticket — pveproxy parses it as-is.
			"Cookie": []string{"PVEAuthCookie=" + session.Ticket},
		}
	} else {
		wsHeader = http.Header{
			"Authorization": []string{
				fmt.Sprintf("PVEAPIToken=%s=%s", inst.APITokenID, inst.APITokenSecret),
			},
		}
	}
	dialOpts := &websocket.DialOptions{
		Subprotocols: []string{"binary"},
		HTTPHeader:   wsHeader,
		HTTPClient:   proxmox.InsecureHTTPClient(),
	}

	conn, wsResp, err := websocket.Dial(ctx, wsURL, dialOpts)
	if wsResp != nil && wsResp.Body != nil {
		_ = wsResp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("dial termproxy websocket %s: %w", wsURL, err)
	}
	defer func() { _ = conn.CloseNow() }()

	// --- Step 5: Send auth line: "<authid>:<vncticket>\n" ---
	// termproxy reads this first, validates (via /access/ticket or /access/vncticket
	// depending on Proxmox version), then sends "OK".
	// authid must match the identity used when assembling the VNC ticket:
	// - session auth: inst.Username (e.g. root@pam)
	// - token auth:   inst.APITokenID (e.g. root@pam!proxpass)
	var authid string
	if session != nil {
		authid = session.Username
	} else {
		authid = inst.APITokenID
	}
	authLine := fmt.Sprintf("%s:%s\n", authid, ticket.Ticket)
	if err := conn.Write(ctx, websocket.MessageBinary, []byte(authLine)); err != nil {
		return fmt.Errorf("send auth line: %w", err)
	}

	// --- Step 6: Read "OK" response ---
	// termproxy sends "OK" after validating the auth line. Any bytes after
	// "OK" in the same frame are the start of the terminal stream.
	_, firstMsg, err := conn.Read(ctx)
	if err != nil {
		var closeErr websocket.CloseError
		if errors.As(err, &closeErr) {
			logger.Printf("termproxy: server closed (code=%d reason=%q url=%s)",
				closeErr.Code, closeErr.Reason, wsURL)
			return fmt.Errorf("termproxy server closed: code=%d reason=%q",
				closeErr.Code, closeErr.Reason)
		}
		logger.Printf("termproxy: handshake failed (url=%s): %v", wsURL, err)
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

	// --- Step 7: Send initial resize if PTY requested ---
	if ptyReq != nil {
		resizeMsg := fmt.Sprintf("1:%d:%d:", ptyReq.Width, ptyReq.Height)
		if err := conn.Write(ctx, websocket.MessageBinary, []byte(resizeMsg)); err != nil {
			return fmt.Errorf("send initial resize: %w", err)
		}
	}

	// --- Step 8: Bidirectional bridge ---
	done := make(chan struct{})
	var wg sync.WaitGroup

	// Forward SSH window-change and keepalive.
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

	// SSH client → WebSocket: frame as "0:<len>:<data>"
	go func() {
		buf := make([]byte, 4096)
		for {
			n, readErr := clientChan.Read(buf)
			if n > 0 {
				msg := fmt.Sprintf("0:%d:%s", n, buf[:n])
				if writeErr := conn.Write(ctx, websocket.MessageBinary, []byte(msg)); writeErr != nil {
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

	// WebSocket → SSH client: raw bytes (server sends binary terminal data).
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
