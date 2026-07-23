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
	sshHost     string // used to identify this node among the cluster nodes
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
		sshHost:     inst.SSHHost,
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
// node that matches inst.SSHHost. The node name is resolved via the Proxmox
// REST API itself (no SSH required): /api2/json/nodes returns all node names,
// and we match SSHHost against them by exact match or FQDN prefix.
func (c *APIClient) DiscoverGuests(ctx context.Context) ([]*models.Guest, error) {
	node, err := c.resolveNodeName(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve node name: %w", err)
	}

	cts, err := c.getNodeGuests(ctx, node, "lxc", models.GuestTypeCT)
	if err != nil {
		return nil, fmt.Errorf("get lxc on node %s: %w", node, err)
	}

	vms, err := c.getNodeGuests(ctx, node, "qemu", models.GuestTypeVM)
	if err != nil {
		return nil, fmt.Errorf("get qemu on node %s: %w", node, err)
	}

	return append(cts, vms...), nil
}

// ResolveNodeName returns the Proxmox node name for this instance.
//
// When sshHost is non-empty, it is matched against the cluster node list
// (case-insensitive exact match, or FQDN-prefix: "rome.domain" → "rome").
//
// When sshHost is empty, the local node is identified via
// GET /api2/json/cluster/status which marks the node serving the request
// with local=1. This is the correct approach for termproxy mode where
// --api-url already points at the target node.
func (c *APIClient) ResolveNodeName(ctx context.Context, sshHost string) (string, error) {
	if sshHost == "" {
		// No ssh-host hint: ask the API which node is local (serves this request).
		return c.getLocalNode(ctx)
	}

	nodes, err := c.getNodes(ctx)
	if err != nil {
		return "", err
	}

	ssh := strings.ToLower(sshHost)
	for _, node := range nodes {
		n := strings.ToLower(node)
		if ssh == n || strings.HasPrefix(ssh, n+".") {
			return node, nil
		}
	}
	return "", fmt.Errorf("no Proxmox node matches ssh-host %q (known nodes: %s)",
		sshHost, strings.Join(nodes, ", "))
}

// getLocalNode calls GET /api2/json/cluster/status and returns the node name
// whose "local" field is 1 — that is, the node serving this API request.
// This is how we determine which node --api-url points at without requiring
// the user to supply --ssh-host in termproxy mode.
func (c *APIClient) getLocalNode(ctx context.Context) (string, error) {
	body, err := c.doGet(ctx, "/api2/json/cluster/status")
	if err != nil {
		return "", fmt.Errorf("get cluster status: %w", err)
	}

	var resp clusterStatusResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("decode cluster status: %w", err)
	}

	for _, entry := range resp.Data {
		if entry.Type == "node" && entry.Local == 1 {
			return entry.Name, nil
		}
	}
	return "", fmt.Errorf("no local node found in cluster status response")
}

// resolveNodeName is the internal wrapper used by DiscoverGuests.
// It resolves c.sshHost against the cluster node list.
func (c *APIClient) resolveNodeName(ctx context.Context) (string, error) {
	return c.ResolveNodeName(ctx, c.sshHost)
}

// --- Proxmox API response structures ---

type nodesResponse struct {
	Data []nodeEntry `json:"data"`
}

type nodeEntry struct {
	Node   string `json:"node"`
	Status string `json:"status"`
}

type clusterStatusResponse struct {
	Data []clusterStatusEntry `json:"data"`
}

type clusterStatusEntry struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Local int    `json:"local"` // 1 when this entry is the local node
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

// InsecureHTTPClient returns an *http.Client that skips TLS certificate
// verification. Used by the termproxy WebSocket dialer to connect to
// Proxmox hosts that use self-signed certificates.
func InsecureHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Proxmox self-signed certs
			},
		},
	}
}
