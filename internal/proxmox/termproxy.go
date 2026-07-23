package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"proxpass/internal/models"
)

// SessionTicket holds a Proxmox user session ticket obtained from
// POST /api2/json/access/ticket. The cookie value authenticates the
// vncwebsocket WebSocket request as the underlying user (e.g. root@pam),
// which is required for verify_vnc_ticket to succeed.
type SessionTicket struct {
	Ticket              string // value for PVEAuthCookie
	CSRFPreventionToken string
	Username            string // e.g. "root@pam"
}

// sessionTicketResponse is the JSON envelope from POST /access/ticket.
type sessionTicketResponse struct {
	Data struct {
		Ticket              string `json:"ticket"`
		CSRFPreventionToken string `json:"CSRFPreventionToken"`
		Username            string `json:"username"`
	} `json:"data"`
}

// GetSessionTicket obtains a Proxmox user session ticket via
// POST /api2/json/access/ticket using the provided username and password.
// The returned PVEAuthCookie ticket authenticates the vncwebsocket WebSocket
// and termproxy auth line with the user identity (e.g. root@pam) rather
// than the API token identity (e.g. root@pam!proxpass).
// This is required for older Proxmox versions whose termproxy binary
// verifies via /access/ticket (not /access/vncticket).
func (c *APIClient) GetSessionTicket(ctx context.Context, username, password string) (*SessionTicket, error) {
	body := url.Values{}
	body.Set("username", username)
	body.Set("password", password)

	reqURL := c.baseURL + "/api2/json/access/ticket"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL,
		bytes.NewBufferString(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", reqURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s: status %d: %s", reqURL, resp.StatusCode, string(respBody))
	}

	var st sessionTicketResponse
	if err := json.Unmarshal(respBody, &st); err != nil {
		return nil, fmt.Errorf("decode session ticket: %w", err)
	}
	if st.Data.Ticket == "" {
		return nil, fmt.Errorf("session ticket response contained no ticket")
	}
	return &SessionTicket{
		Ticket:              st.Data.Ticket,
		CSRFPreventionToken: st.Data.CSRFPreventionToken,
		Username:            st.Data.Username,
	}, nil
}

// TermProxyTicket holds the result of the Proxmox termproxy POST endpoint.
type TermProxyTicket struct {
	Ticket string
	Port   int
	User   string
}

// termProxyResponse is the JSON envelope returned by POST .../termproxy.
// Proxmox returns the port as a JSON string (e.g. "5900"), not a number.
type termProxyResponse struct {
	Data struct {
		Ticket string `json:"ticket"`
		Port   string `json:"port"`
		User   string `json:"user"`
	} `json:"data"`
}

// CreateTermProxyTicketWithSession calls the Proxmox REST API to create a
// termproxy session, authenticated with a user session cookie rather than
// the API token. This is necessary because the vncwebsocket endpoint
// validates the VNC ticket against the authenticated user identity from the
// PVEAuthCookie, and API token identities (user@realm!token) differ from
// the underlying user identity (user@realm) that PVEAuthCookie carries.
//
// Endpoints:
//
//	CT: POST /api2/json/nodes/{node}/lxc/{vmid}/termproxy
//	VM: POST /api2/json/nodes/{node}/qemu/{vmid}/termproxy
func (c *APIClient) CreateTermProxyTicketWithSession(
	ctx context.Context,
	node string,
	guest *models.Guest,
	session *SessionTicket,
) (*TermProxyTicket, error) {
	body, err := c.doPostWithSession(ctx, termProxyPath(node, guest), session)
	if err != nil {
		return nil, err
	}
	return parseTermProxyTicket(body)
}

// CreateTermProxyTicket calls the Proxmox termproxy endpoint using API token
// auth. Kept for test compatibility; production code uses CreateTermProxyTicketWithSession.
func (c *APIClient) CreateTermProxyTicket(ctx context.Context, node string, guest *models.Guest) (*TermProxyTicket, error) {
	body, err := c.doPost(ctx, termProxyPath(node, guest), nil)
	if err != nil {
		return nil, err
	}
	return parseTermProxyTicket(body)
}

// termProxyPath returns the API path for the termproxy endpoint.
func termProxyPath(node string, guest *models.Guest) string {
	var kind string
	switch guest.Type {
	case models.GuestTypeCT:
		kind = "lxc"
	case models.GuestTypeVM:
		kind = "qemu"
	default:
		kind = "qemu"
	}
	return fmt.Sprintf("/api2/json/nodes/%s/%s/%d/termproxy", node, kind, guest.ProxmoxID)
}

// parseTermProxyTicket decodes the JSON body from a termproxy POST response.
func parseTermProxyTicket(body []byte) (*TermProxyTicket, error) {
	var resp termProxyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode termproxy response: %w", err)
	}
	port, err := strconv.Atoi(resp.Data.Port)
	if err != nil {
		return nil, fmt.Errorf("decode termproxy port %q: %w", resp.Data.Port, err)
	}
	return &TermProxyTicket{
		Ticket: resp.Data.Ticket,
		Port:   port,
		User:   resp.Data.User,
	}, nil
}

// doPostWithSession performs a cookie-authenticated POST using a user session
// ticket instead of the API token. Required for termproxy and vncwebsocket.
func (c *APIClient) doPostWithSession(ctx context.Context, path string, session *SessionTicket) ([]byte, error) {
	reqURL := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("new request %s: %w", reqURL, err)
	}
	// Cookie value must be the raw ticket — Proxmox parses it as-is; URL-encoding breaks auth.
	req.Header.Set("Cookie", "PVEAuthCookie="+session.Ticket)
	req.Header.Set("CSRFPreventionToken", session.CSRFPreventionToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", reqURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body %s: %w", reqURL, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s: status %d: %s", reqURL, resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// doPost performs an API-token-authenticated POST and returns the response body.
// bodyPayload may be nil for endpoints that require no request body.
func (c *APIClient) doPost(ctx context.Context, path string, bodyPayload []byte) ([]byte, error) {
	reqURL := c.baseURL + path

	var bodyReader io.Reader
	if bodyPayload != nil {
		bodyReader = bytes.NewReader(bodyPayload)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("new request %s: %w", reqURL, err)
	}
	req.Header.Set("Authorization",
		fmt.Sprintf("PVEAPIToken=%s=%s", c.tokenID, c.tokenSecret))
	if bodyPayload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", reqURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body %s: %w", reqURL, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s: status %d: %s", reqURL, resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
