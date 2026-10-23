package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"

	"proxpass/internal/models"
	"proxpass/internal/proxmox"
)

// connectTermProxy attaches the terminal to a guest console over the Proxmox
// termproxy WebSocket, which needs no SSH credentials on the Proxmox host.
//
// Protocol (derived from the proxmox-termproxy Rust source):
//   - Input:     "0:<len>:<data>" — len is ASCII decimal, data appended raw.
//   - Output:    raw PTY bytes, unframed; forward verbatim.
//   - Resize:    "1:<cols>:<rows>:"
//   - Keepalive: "2" every 30s, or termproxy drops the idle connection.
//
// Requires PVE 9 with pve-manager >= 9.0.13 and proxmox-termproxy >= 1.1.0
// (the --vncticket-endpoint flag). PVE 8 rejects API token IDs as usernames.
//
//nolint:gocognit,gocyclo,funlen // sequential protocol steps plus teardown
func connectTermProxy(
	term *Terminal,
	guest *models.Guest,
	inst *models.ProxmoxInstance,
	logger *log.Logger,
	label string,
) error {
	term.normalize()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Step 1: create the termproxy ticket ---
	apiClient, err := proxmox.NewAPIClient(inst)
	if err != nil {
		return fmt.Errorf("build api client: %w", err)
	}
	ticket, err := apiClient.CreateTermProxyTicket(ctx, inst.Node, guest)
	if err != nil {
		return fmt.Errorf("create termproxy ticket: %w", err)
	}
	logger.Printf("termproxy: ticket obtained (port=%d user=%q)", ticket.Port, ticket.User)

	// --- Step 2: build the vncwebsocket URL ---
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

	// --- Step 3: dial ---
	// The endpoint requires the "binary" subprotocol and accepts API token
	// auth via the Authorization header (pve-manager >= 9.0.13).
	dialOpts := &websocket.DialOptions{
		Subprotocols: []string{"binary"},
		HTTPHeader: http.Header{
			"Authorization": []string{
				fmt.Sprintf("PVEAPIToken=%s=%s", inst.APITokenID, inst.APITokenSecret),
			},
		},
		HTTPClient: proxmox.HTTPClient(inst.InsecureTLS),
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

	// Remove the message size limit.
	//
	// coder/websocket defaults to 32768 bytes per message and fails the read
	// when a message exceeds it, discarding what it had already buffered.
	// termproxy forwards raw PTY output, so a guest writing faster than the
	// terminal drains -- `docker logs' on a busy container, a kernel build,
	// anything that dumps -- produces a single frame past that limit. The
	// session then died mid-escape-sequence partway through the output.
	//
	// A limit protects a server from a client that claims an enormous
	// message. This is a terminal stream from a host the deployment already
	// trusts for everything else, and there is no size at which the next
	// chunk of a console becomes illegitimate, so there is nothing for a
	// bound to express. Raising it to some larger number would only move the
	// same failure further out.
	conn.SetReadLimit(-1)

	// --- Step 4: authenticate with "<authid>:<ticket>\n" ---
	authLine := fmt.Sprintf("%s:%s\n", inst.APITokenID, ticket.Ticket)
	if err := conn.Write(ctx, websocket.MessageBinary, []byte(authLine)); err != nil {
		return fmt.Errorf("send auth line: %w", err)
	}

	// --- Step 5: read the "OK" handshake ---
	// termproxy writes exactly two bytes; anything past index 1 in the same
	// frame is early terminal output.
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
		if _, err := term.Out.Write(handshake[2:]); err != nil {
			return fmt.Errorf("write initial terminal data: %w", err)
		}
	}

	// --- Step 6: reserve the bar's row and send the initial size ---
	bar, guestOut, guestRows := startBar(term, label, EscapeHint)
	if bar != nil {
		defer bar.Stop()
	} else {
		// Parity with the ssh path: clear the screen when no bar does it for us.
		clearScreenNoBar(term)
	}
	if err := conn.Write(ctx, websocket.MessageBinary,
		[]byte(fmt.Sprintf("1:%d:%d:", term.Width, guestRows))); err != nil {
		return fmt.Errorf("send initial resize: %w", err)
	}

	// --- Step 7: bridge ---
	done := make(chan struct{})

	// Resizes and keepalives.
	//
	// resizes is a local copy: the Terminal belongs to the caller and its
	// SIGWINCH goroutine still sends on that channel, so nilling the struct
	// field here would be a data race.
	resizes := term.Resizes
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// Message type 2 is the termproxy keepalive ping.
				_ = conn.Write(ctx, websocket.MessageBinary, []byte("2"))
			case size, ok := <-resizes:
				if !ok {
					// Stop selecting on a closed channel, but keep the
					// keepalive running.
					resizes = nil
					continue
				}
				// Report the height the guest actually has, and repaint the
				// bar at its new position.
				rows := size.Height
				if bar != nil {
					rows = bar.Resize(size.Width, size.Height)
				}
				_ = conn.Write(ctx, websocket.MessageBinary,
					[]byte(fmt.Sprintf("1:%d:%d:", size.Width, rows)))
			}
		}
	}()

	// stdin → WebSocket, framed as "0:<len>:<data>".
	//
	// The header and payload are concatenated as bytes rather than formatted
	// with %s: routing the slice through a string would corrupt non-UTF-8
	// input (arrow keys, escape sequences) and invalidate the declared length.
	// Ctrl+A X reports EOF, and closing the WebSocket below is all the
	// teardown this transport needs: the read loop then fails and returns.
	// No signal is required because termproxy owns the guest-side process.
	go func() {
		src := newEscapeReader(term.In, nil)
		buf := make([]byte, 4096)
		for {
			n, readErr := src.Read(buf)
			if n > 0 {
				msg := append([]byte(fmt.Sprintf("0:%d:", n)), buf[:n]...)
				if writeErr := conn.Write(ctx, websocket.MessageBinary, msg); writeErr != nil {
					return
				}
			}
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) {
					logger.Printf("termproxy: terminal read error: %v", readErr)
				}
				_ = conn.Close(websocket.StatusNormalClosure, "")
				return
			}
		}
	}()

	// WebSocket → stdout: raw PTY bytes, no framing.
	//
	// Both exits are logged. This loop ending is how the session ends, so a
	// failure here is the only account of why -- and it used to break
	// silently, which is what made a dropped read look like a crash: the
	// output stopped, the bar's teardown ran, and nothing anywhere said
	// anything had gone wrong.
	for {
		_, data, readErr := conn.Read(ctx)
		if readErr != nil {
			if !isNormalClose(readErr) {
				logger.Printf("termproxy: guest %q read error: %v", guest.Name, readErr)
			}
			break
		}
		if _, writeErr := guestOut.Write(data); writeErr != nil {
			logger.Printf("termproxy: guest %q terminal write error: %v", guest.Name, writeErr)
			break
		}
	}
	close(done)
	return nil
}

// isNormalClose reports whether err is an ordinary end of session rather than
// a fault.
//
// A console ends when the user leaves, which arrives as a close handshake or
// a canceled context. Those are not worth logging; anything else is.
func isNormalClose(err error) bool {
	// An if rather than a switch: only two of the fifteen close codes are
	// ordinary here, and every other one is a fault worth reporting.
	if status := websocket.CloseStatus(err); status == websocket.StatusNormalClosure ||
		status == websocket.StatusGoingAway {
		return true
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, io.EOF)
}

// buildVNCWebSocketURL constructs the URL for the Proxmox vncwebsocket
// endpoint. The WebSocket targets the same host:port as the API URL; the
// Proxmox API proxies through to the termproxy binary on localhost.
func buildVNCWebSocketURL(
	apiURL *url.URL,
	node, kind string,
	vmid int,
	ticket *proxmox.TermProxyTicket,
) string {
	wsScheme := "ws"
	if apiURL.Scheme == "https" {
		wsScheme = "wss"
	}
	q := url.Values{}
	q.Set("port", fmt.Sprintf("%d", ticket.Port))
	q.Set("vncticket", ticket.Ticket)

	u := &url.URL{
		Scheme:   wsScheme,
		Host:     apiURL.Host,
		Path:     fmt.Sprintf("/api2/json/nodes/%s/%s/%d/vncwebsocket", node, kind, vmid),
		RawQuery: q.Encode(),
	}
	return u.String()
}
