package proxmox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"proxpass/internal/models"
)

// APIClient communicates with the Proxmox VE REST API.
type APIClient struct {
	baseURL     string
	tokenID     string
	tokenSecret string
	httpClient  *http.Client
}

// NewAPIClient creates an API client for the given Proxmox instance.
// Returns an error if inst.APIURL is missing a scheme (e.g. "pve:8006"
// instead of "https://pve:8006"), which would cause url.Parse to treat
// the hostname as a scheme and silently drop the port.
func NewAPIClient(inst *models.ProxmoxInstance) (*APIClient, error) {
	parsed, err := url.Parse(strings.TrimRight(inst.APIURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid api-url %q: %w", inst.APIURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid api-url %q: must start with http:// or https://", inst.APIURL)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid api-url %q: missing host", inst.APIURL)
	}
	// Use the trimmed original string (not parsed.String()) to preserve
	// the URL exactly as provided without any normalization side-effects.
	return &APIClient{
		baseURL:     strings.TrimRight(inst.APIURL, "/"),
		tokenID:     inst.APITokenID,
		tokenSecret: inst.APITokenSecret,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // Proxmox often uses self-signed certs
				},
			},
		},
	}, nil
}

// DiscoverGuests queries the Proxmox API for all nodes, then fetches LXC
// containers and QEMU VMs from each node, returning the combined guest list.
func (c *APIClient) DiscoverGuests(ctx context.Context) ([]*models.Guest, error) {
	nodes, err := c.getNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("get nodes: %w", err)
	}

	var guests []*models.Guest
	for _, node := range nodes {
		cts, err := c.getNodeGuests(ctx, node, "lxc", models.GuestTypeCT)
		if err != nil {
			return nil, fmt.Errorf("get lxc on node %s: %w", node, err)
		}
		guests = append(guests, cts...)

		vms, err := c.getNodeGuests(ctx, node, "qemu", models.GuestTypeVM)
		if err != nil {
			return nil, fmt.Errorf("get qemu on node %s: %w", node, err)
		}
		guests = append(guests, vms...)
	}

	return guests, nil
}

// --- Proxmox API response structures ---

type nodesResponse struct {
	Data []nodeEntry `json:"data"`
}

type nodeEntry struct {
	Node   string `json:"node"`
	Status string `json:"status"`
}

type guestsResponse struct {
	Data []guestEntry `json:"data"`
}

type guestEntry struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// --- internal helpers ---

// doGet performs an authenticated GET and returns the response body.
func (c *APIClient) doGet(ctx context.Context, path string) ([]byte, error) {
	reqURL := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("new request %s: %w", reqURL, err)
	}
	req.Header.Set("Authorization",
		fmt.Sprintf("PVEAPIToken=%s=%s", c.tokenID, c.tokenSecret))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", reqURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body %s: %w", reqURL, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d: %s", reqURL, resp.StatusCode, string(body))
	}

	return body, nil
}

// getNodes returns the list of node names from the cluster.
func (c *APIClient) getNodes(ctx context.Context) ([]string, error) {
	body, err := c.doGet(ctx, "/api2/json/nodes")
	if err != nil {
		return nil, err
	}

	var resp nodesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode nodes response: %w", err)
	}

	names := make([]string, 0, len(resp.Data))
	for _, n := range resp.Data {
		names = append(names, n.Node)
	}
	return names, nil
}

// getNodeGuests fetches guests of a given kind ("lxc" or "qemu") from a node.
func (c *APIClient) getNodeGuests(ctx context.Context, node, kind string, guestType models.GuestType) ([]*models.Guest, error) {
	path := fmt.Sprintf("/api2/json/nodes/%s/%s", node, kind)
	body, err := c.doGet(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp guestsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode %s response for node %s: %w", kind, node, err)
	}

	guests := make([]*models.Guest, 0, len(resp.Data))
	for _, entry := range resp.Data {
		guests = append(guests, &models.Guest{
			Type:      guestType,
			ProxmoxID: entry.VMID,
			Name:      entry.Name,
			Status:    normalizeStatus(entry.Status),
		})
	}
	return guests, nil
}

// Compile-time check: *APIClient must satisfy GuestDiscoverer.
var _ GuestDiscoverer = (*APIClient)(nil)

// DefaultDiscovererFactory creates an APIClient-based discoverer.
// If the instance URL is invalid it returns a discoverer that immediately
// returns an error, so the error surfaces at discovery time rather than panicking.
func DefaultDiscovererFactory(inst *models.ProxmoxInstance) GuestDiscoverer {
	client, err := NewAPIClient(inst)
	if err != nil {
		return &errDiscoverer{err: err}
	}
	return client
}

// errDiscoverer is a GuestDiscoverer that always returns a fixed error.
type errDiscoverer struct{ err error }

func (e *errDiscoverer) DiscoverGuests(_ context.Context) ([]*models.Guest, error) {
	return nil, e.err
}

// normalizeStatus maps a raw status string to one of the known Status
// constants. Unknown values default to StatusStopped.
func normalizeStatus(raw string) models.Status {
	switch strings.ToLower(raw) {
	case "running":
		return models.StatusRunning
	case "stopped":
		return models.StatusStopped
	default:
		return models.StatusStopped
	}
}
