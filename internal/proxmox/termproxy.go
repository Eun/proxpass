package proxmox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"proxpass/internal/models"
)

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

// CreateTermProxyTicket calls the Proxmox termproxy endpoint using API token auth.
// Requires Proxmox VE 9 (pve-manager >= 9.0.13, proxmox-termproxy >= 1.1.0).
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

// doPost performs an API-token-authenticated POST and returns the response body.
// bodyPayload may be nil for endpoints that require no request body.
func (c *APIClient) doPost(ctx context.Context, path string, bodyPayload []byte) ([]byte, error) {
	reqURL := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, http.NoBody)
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
