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

type ProxmoxInstance struct {
	ID       int64  `json:"id"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	APIKey   string `json:"api_key"`
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
