package testenv

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

const apiDataKey = "data"

// MockAPIServer simulates the Proxmox VE REST API.
type MockAPIServer struct {
	mu         sync.RWMutex
	nodes      map[string]*mockNode // node name → guests
	token      string               // expected "tokenID=tokenSecret"
	server     *httptest.Server     // non-nil for test mode (httptest)
	httpServer *http.Server         // non-nil for standalone mode
}

type mockNode struct {
	LXC  []mockGuest
	QEMU []mockGuest
}

type mockGuest struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// NewMockAPIServer creates a mock Proxmox API server with the given
// API token for authentication. Call AddNode/AddLXC/AddQEMU to
// populate it, then use URL() to point an APIClient at it.
func NewMockAPIServer(tokenID, tokenSecret string) *MockAPIServer {
	m := &MockAPIServer{
		nodes: make(map[string]*mockNode),
		token: tokenID + "=" + tokenSecret,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes", m.handleNodes)
	// Use a catch-all pattern and parse the path manually for
	// /api2/json/nodes/{node}/lxc and /api2/json/nodes/{node}/qemu
	mux.HandleFunc("/api2/json/nodes/", m.handleNodeGuests)
	m.server = httptest.NewTLSServer(mux)
	return m
}

func (m *MockAPIServer) URL() string {
	return m.server.URL
}

func (m *MockAPIServer) Close() {
	if m.server != nil {
		m.server.Close()
	}
	if m.httpServer != nil {
		_ = m.httpServer.Shutdown(context.Background())
	}
}

// Handler returns the underlying http.Handler for standalone use.
func (m *MockAPIServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes", m.handleNodes)
	mux.HandleFunc("/api2/json/nodes/", m.handleNodeGuests)
	return mux
}

// LoadFromConfig populates the mock API server from a MockConfig.
func (m *MockAPIServer) LoadFromConfig(cfg *MockConfig) {
	for _, node := range cfg.Nodes {
		for _, g := range node.Guests {
			switch g.Type {
			case guestTypeLXC:
				m.AddLXC(node.Name, g.VMID, g.Name, g.Status)
			case guestTypeQEMU:
				m.AddQEMU(node.Name, g.VMID, g.Name, g.Status)
			}
		}
	}
}

// NewMockAPIServerStandalone creates a mock API server that will
// listen on a fixed address (e.g. ":8006") using plain HTTP.
// Call ListenAndServe to start it. For unit tests, use
// NewMockAPIServer which uses httptest on a random port.
func NewMockAPIServerStandalone(tokenID, tokenSecret string) *MockAPIServer {
	return &MockAPIServer{
		nodes: make(map[string]*mockNode),
		token: tokenID + "=" + tokenSecret,
	}
}

// ListenAndServe starts the mock API on the given address using
// plain HTTP. It blocks until the server is shut down.
func (m *MockAPIServer) ListenAndServe(addr string) error {
	m.httpServer = &http.Server{
		Addr:              addr,
		Handler:           m.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	return m.httpServer.Serve(ln)
}

// AddLXC adds a mock LXC container to a node.
func (m *MockAPIServer) AddLXC(node string, vmid int, name, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.ensureNode(node)
	n.LXC = append(n.LXC, mockGuest{VMID: vmid, Name: name, Status: status})
}

// AddQEMU adds a mock QEMU VM to a node.
func (m *MockAPIServer) AddQEMU(node string, vmid int, name, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.ensureNode(node)
	n.QEMU = append(n.QEMU, mockGuest{VMID: vmid, Name: name, Status: status})
}

func (m *MockAPIServer) ensureNode(name string) *mockNode {
	if m.nodes[name] == nil {
		m.nodes[name] = &mockNode{}
	}
	return m.nodes[name]
}

func (m *MockAPIServer) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	expected := "PVEAPIToken=" + m.token
	if auth != expected {
		http.Error(w, `{"errors":{"username":"invalid credentials"}}`, http.StatusUnauthorized)
		return false
	}
	return true
}

func (m *MockAPIServer) handleNodes(w http.ResponseWriter, r *http.Request) {
	if !m.checkAuth(w, r) {
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	type nodeEntry struct {
		Node   string `json:"node"`
		Status string `json:"status"`
	}
	var entries []nodeEntry
	for name := range m.nodes {
		entries = append(entries, nodeEntry{Node: name, Status: "online"})
	}
	writeJSON(w, map[string]any{apiDataKey: entries})
}

func (m *MockAPIServer) handleNodeGuests(w http.ResponseWriter, r *http.Request) {
	if !m.checkAuth(w, r) {
		return
	}

	// Parse: /api2/json/nodes/{node}/lxc or /api2/json/nodes/{node}/qemu
	path := strings.TrimPrefix(r.URL.Path, "/api2/json/nodes/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	nodeName := parts[0]
	kind := parts[1] // "lxc" or "qemu"

	m.mu.RLock()
	defer m.mu.RUnlock()

	n := m.nodes[nodeName]
	if n == nil {
		writeJSON(w, map[string]any{apiDataKey: []any{}})
		return
	}

	var guests []mockGuest
	switch kind {
	case guestTypeLXC:
		guests = n.LXC
	case guestTypeQEMU:
		guests = n.QEMU
	default:
		http.NotFound(w, r)
		return
	}

	writeJSON(w, map[string]any{apiDataKey: guests})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
