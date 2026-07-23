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
	node        string // cluster node to discover guests from (set from inst.SSHHost)
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
	return &APIClient{
		// Use the trimmed original string, not parsed.String(), to guarantee
		// the port is preserved exactly as the user specified it.
		baseURL:     strings.TrimRight(inst.APIURL, "/"),
		tokenID:     inst.APITokenID,
		tokenSecret: inst.APITokenSecret,
		node:        inst.SSHHost,
		httpClient: &http.Client{
			// Never follow redirects. Proxmox can redirect to a URL that
			// drops the port (e.g. https://host:8006 → https://host),
			// which would silently connect to port 443 instead.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // Proxmox often uses self-signed certs
				},
			},
		},
	}, nil
}

// DiscoverGuests fetches LXC containers and QEMU VMs from the single cluster
// node identified by inst.SSHHost. Only guests on this node can be entered via
// the configured SSH host, so we deliberately scope discovery to that node.
func (c *APIClient) DiscoverGuests(ctx context.Context) ([]*models.Guest, error) {
	cts, err := c.getNodeGuests(ctx, c.node, "lxc", models.GuestTypeCT)
	if err != nil {
		return nil, fmt.Errorf("get lxc on node %s: %w", c.node, err)
	}

	vms, err := c.getNodeGuests(ctx, c.node, "qemu", models.GuestTypeVM)
	if err != nil {
		return nil, fmt.Errorf("get qemu on node %s: %w", c.node, err)
	}

	return append(cts, vms...), nil
}

// --- Proxmox API response structures ---

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
