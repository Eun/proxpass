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

	SSHHost    string `json:"ssh_host"`
	SSHPort    int    `json:"ssh_port"`
	SSHUser    string `json:"ssh_user"`
	SSHKeyPath string `json:"ssh_key_path"`
	SSHKey     string `json:"ssh_key"` // PEM-encoded private key (stored in DB; preferred over SSHKeyPath when non-empty)
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

// SessionIdentity is who a session turned out to be, as resolved from the
// key that authenticated it.
//
// It is stored against a bearer token at authentication time and handed back
// when that token is redeemed, so that `proxpass serve' can answer "who are
// you" without the session having to claim anything. The session's own view
// of this lives in internal/session.Identity; this is the part that has to
// survive in the database between the two processes.
//
// ClientID is 0 for the administrator, who has no client row.
type SessionIdentity struct {
	// LoginName is what the caller typed in `ssh <name>@host'.
	//
	// It is a REQUEST PARAMETER, not an identity. Any name the directory
	// does not already serve resolves to an alias, so anybody can pick
	// anybody else's -- which is why the session also accepts it as a
	// guest target ("ssh ct100@host"). Never log it as the actor and never
	// make an authorization decision from it: use IdentityName and the
	// IsAdmin/ClientID fields instead.
	LoginName string `json:"login_name"`

	// IdentityName is WHO THE CALLER IS: the clients.name row the
	// authenticating key belongs to, or the administrator's name.
	//
	// Resolved by `proxpass authorized-keys', which runs as root before the
	// session exists and therefore knows which key is which. The session
	// cannot influence it. This is the name to log, the name to show, and
	// the name an operator will grep for.
	//
	// It is deliberately not called IdentityName any more: that invited
	// treating it as a cosmetic string safe to truncate or localize, which
	// would quietly corrupt the audit trail.
	IdentityName string `json:"identity_name"`

	IsAdmin  bool  `json:"is_admin"`
	ClientID int64 `json:"client_id"`
}
