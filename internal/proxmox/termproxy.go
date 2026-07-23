package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"proxpass/internal/models"
)

// TermProxyTicket holds the result of the Proxmox termproxy POST endpoint.
type TermProxyTicket struct {
	Ticket string
	Port   int
	User   string
}

// termProxyResponse is the JSON envelope returned by POST .../termproxy.
type termProxyResponse struct {
	Data struct {
		Ticket string `json:"ticket"`
		Port   int    `json:"port"`
		User   string `json:"user"`
	} `json:"data"`
}

// CreateTermProxyTicket calls the Proxmox REST API to create a termproxy
// session for the given guest on the specified node. It returns a ticket
// and port that can be used to open the corresponding VNC WebSocket.
//
// Endpoints:
//
//	CT: POST /api2/json/nodes/{node}/lxc/{vmid}/termproxy
//	VM: POST /api2/json/nodes/{node}/qemu/{vmid}/termproxy
func (c *APIClient) CreateTermProxyTicket(ctx context.Context, node string, guest *models.Guest) (*TermProxyTicket, error) {
	var kind string
	switch guest.Type {
	case models.GuestTypeCT:
		kind = "lxc"
	case models.GuestTypeVM:
		kind = "qemu"
	default:
		return nil, fmt.Errorf("unknown guest type %q", guest.Type)
	}

	path := fmt.Sprintf("/api2/json/nodes/%s/%s/%d/termproxy", node, kind, guest.ProxmoxID)
	body, err := c.doPost(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("termproxy POST for %s/%d: %w", kind, guest.ProxmoxID, err)
	}

	var resp termProxyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode termproxy response: %w", err)
	}

	return &TermProxyTicket{
		Ticket: resp.Data.Ticket,
		Port:   resp.Data.Port,
		User:   resp.Data.User,
	}, nil
}

// doPost performs an authenticated POST and returns the response body.
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
