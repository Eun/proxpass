package testenv

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	guestTypeLXC   = "lxc"
	guestTypeQEMU  = "qemu"
	defaultSSHUser = "root"
	statusRunning  = "running"
	statusStopped  = "stopped"
)

// MockConfig is the YAML configuration for the mock Proxmox service.
type MockConfig struct {
	API   APIConfig    `yaml:"api"`
	SSH   SSHConfig    `yaml:"ssh"`
	Nodes []NodeConfig `yaml:"nodes"`
}

// APIConfig configures the mock Proxmox REST API.
type APIConfig struct {
	ListenAddr  string `yaml:"listen_addr"`  // e.g. ":8006"
	TokenID     string `yaml:"token_id"`     // e.g. "testuser@pam!testtoken"
	TokenSecret string `yaml:"token_secret"` // e.g. "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
}

// SSHConfig configures the mock Proxmox SSH server.
type SSHConfig struct {
	ListenAddr string `yaml:"listen_addr"` // e.g. ":22"
}

// NodeConfig defines a PVE node and its guests.
type NodeConfig struct {
	Name   string        `yaml:"name"`
	Guests []GuestConfig `yaml:"guests"`
}

// GuestConfig defines a single LXC container or QEMU VM.
type GuestConfig struct {
	VMID   int    `yaml:"vmid"`
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`   // "lxc" or "qemu"
	Status string `yaml:"status"` // "running" or "stopped"
}

// LoadConfig reads and parses a YAML config file.
func LoadConfig(path string) (*MockConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg MockConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &cfg, nil
}

// DefaultConfig returns a config with sensible defaults for testing.
func DefaultConfig() *MockConfig {
	return &MockConfig{
		API: APIConfig{
			ListenAddr:  ":8006",
			TokenID:     "testuser@pam!testtoken",
			TokenSecret: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		},
		SSH: SSHConfig{
			ListenAddr: ":2223",
		},
		Nodes: []NodeConfig{
			{
				Name: "pve1",
				Guests: []GuestConfig{
					{VMID: 100, Name: "webserver", Type: guestTypeLXC, Status: statusRunning},
					{VMID: 101, Name: "database", Type: guestTypeLXC, Status: statusRunning},
					{VMID: 200, Name: "devbox", Type: guestTypeQEMU, Status: statusRunning},
					{VMID: 201, Name: "staging", Type: guestTypeQEMU, Status: statusStopped},
				},
			},
		},
	}
}
