package models

type GuestType string

const (
	GuestTypeCT GuestType = "ct"
	GuestTypeVM GuestType = "vm"
)

type Status string

const (
	StatusRunning Status = "running"
	StatusStopped Status = "stopped"
)

// ConnectionType controls how proxpass connects to a guest console.
type ConnectionType string

const (
	// ConnectionTypeTermProxy uses the Proxmox REST API termproxy endpoint
	// and a WebSocket to attach a terminal. This is the default and does not
	// require SSH credentials on the Proxmox host.
	ConnectionTypeTermProxy ConnectionType = "termproxy"

	// ConnectionTypeSSH SSHes into the Proxmox host and runs
	// pct enter / qm terminal. Requires ssh_host and an SSH key.
	ConnectionTypeSSH ConnectionType = "ssh"
)

type ProxmoxInstance struct {
	ID             int64          `json:"id"`
	Name           string         `json:"name"`
	APIURL         string         `json:"api_url"`
	APITokenID     string         `json:"api_token_id"`
	APITokenSecret string         `json:"api_token_secret"`
	ConnectionType ConnectionType `json:"connection_type"` // "termproxy" (default) or "ssh"
	Node           string         `json:"node"`            // resolved Proxmox short node name
	SSHHost        string         `json:"ssh_host"`
	SSHPort        int            `json:"ssh_port"`
	SSHUser        string         `json:"ssh_user"`
	SSHKeyPath     string         `json:"ssh_key_path"`
	SSHKey         string         `json:"ssh_key"` // PEM-encoded private key (stored in DB; preferred over SSHKeyPath when non-empty)
}

type Guest struct {
	ID         int64     `json:"id"`
	Type       GuestType `json:"type"`
	Name       string    `json:"name"`
	Status     Status    `json:"status"`
	ProxmoxID  int       `json:"proxmox_id"`
	InstanceID int64     `json:"instance_id"`
}

type Client struct {
	ID         int64    `json:"id"`
	Name       string   `json:"name"`
	PublicKeys []string `json:"public_keys"`
	GroupIDs   []int64  `json:"group_ids"`
}

type Group struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	ClientIDs []int64 `json:"client_ids"`
}

type RuleType string

const (
	RuleClient RuleType = "client"
	RuleGroup  RuleType = "group"
)

// AccessRuleRow is a flat per-row representation of an access rule (one guest per row).
type AccessRuleRow struct {
	ID        int64    `json:"id"`
	Type      RuleType `json:"type"`
	SubjectID int64    `json:"subject_id"`
	GuestID   int64    `json:"guest_id"`
}

type DefaultAccessPolicy struct {
	AuthorizedClientIDs []int64 `json:"authorized_client_ids"`
	AuthorizedGroupIDs  []int64 `json:"authorized_group_ids"`
}
