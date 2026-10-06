package db

import (
	"context"
	"errors"
	"time"

	"proxpass/internal/models"
)

type Repository interface {
	// Lifecycle
	Close() error

	// Proxmox Instances
	AddProxmoxInstance(ctx context.Context, inst *models.ProxmoxInstance) error
	ListProxmoxInstances(ctx context.Context) ([]*models.ProxmoxInstance, error)
	UpdateProxmoxInstance(ctx context.Context, inst *models.ProxmoxInstance) error
	RemoveProxmoxInstance(ctx context.Context, id int64) error

	// Guests
	UpsertGuest(ctx context.Context, guest *models.Guest) error
	ListGuests(ctx context.Context) ([]*models.Guest, error)
	GetGuestByID(ctx context.Context, id int64) (*models.Guest, error)
	// RemoveGuestsNotIn deletes every guest of an instance whose Proxmox
	// vmid is absent from keep, and returns how many were removed. Access
	// rules referencing those guests are removed with them, since a rule
	// pointing at a vanished guest would silently grant access to whatever
	// reused its row id.
	RemoveGuestsNotIn(ctx context.Context, instanceID int64, keep []int) (int, error)

	// Clients
	AddClient(ctx context.Context, client *models.Client) error
	ListClients(ctx context.Context) ([]*models.Client, error)
	UpdateClient(ctx context.Context, client *models.Client) error
	RemoveClient(ctx context.Context, id int64) error
	GetClientByName(ctx context.Context, name string) (*models.Client, error)

	// Groups
	AddGroup(ctx context.Context, group *models.Group) error
	ListGroups(ctx context.Context) ([]*models.Group, error)
	UpdateGroup(ctx context.Context, group *models.Group) error
	RemoveGroup(ctx context.Context, id int64) error

	// Access Rules
	ListAccessRules(ctx context.Context) ([]*models.AccessRuleRow, error)
	GrantClientAccess(ctx context.Context, clientID int64, guestIDs []int64) error
	GrantGroupAccess(ctx context.Context, groupID int64, guestIDs []int64) error
	RevokeClientAccess(ctx context.Context, clientID, guestID int64) error
	RevokeGroupAccess(ctx context.Context, groupID, guestID int64) error

	// Default Policy
	SetDefaultPolicy(ctx context.Context, policy *models.DefaultAccessPolicy) error
	GetDefaultPolicy(ctx context.Context) (*models.DefaultAccessPolicy, error)

	// Settings
	SetSetting(ctx context.Context, key, value string) error
	GetSetting(ctx context.Context, key string) (string, error)

	// Admin Keys
	AddAdminKey(ctx context.Context, pubKey string) error
	ListAdminKeys(ctx context.Context) ([]string, error)
	RemoveAdminKey(ctx context.Context, pubKey string) error

	// Session Tokens
	//
	// The bearer tokens a session presents to the API instead of opening
	// this database itself. Minted by `proxpass authorized-keys', redeemed
	// by `proxpass serve'. Two processes, so the handoff has to be stored
	// rather than kept in memory.
	MintSessionToken(ctx context.Context, tokenHash string, identity *models.SessionIdentity, now, expiresAt time.Time) error
	// RedeemSessionToken atomically consumes a token and returns whoever it
	// was issued for, or ErrNoSuchToken when it is unknown, expired or has
	// already been used. Single use is the point: see the method comment.
	RedeemSessionToken(ctx context.Context, tokenHash string, now time.Time) (*models.SessionIdentity, error)

	// API Sessions
	//
	// What a session holds after exchanging its one-shot environment token.
	// Unlike the above, LookupAPISession does NOT consume: a session asks
	// repeatedly over its lifetime.
	CreateAPISession(ctx context.Context, tokenHash string, identity *models.SessionIdentity, now, expiresAt time.Time) error
	LookupAPISession(ctx context.Context, tokenHash string, now time.Time) (*models.SessionIdentity, error)
	RevokeAPISession(ctx context.Context, tokenHash string) error

	// Access check (used by the proxy)
	HasAccess(ctx context.Context, clientID, guestID int64) (bool, error)
}

// ErrNoSuchToken reports a bearer token that cannot be redeemed.
//
// Deliberately one error for "never existed", "expired" and "already used":
// the caller turns all three into the same 401, and distinguishing them in
// the API would tell an attacker which guesses were once valid.
var ErrNoSuchToken = errors.New("no such session token")

// Setting keys.
//
// These name configuration that `proxpass serve' persists so that a session
// can read it: sshd gives the session a fresh environment, so anything passed
// as PROXPASS_* reaches serve and nowhere else.
const (
	// SettingPublicEndpoint is the hostname clients use to reach this
	// proxpass, shown in the guest console's status bar. Empty when the
	// deployment has not been told what it is.
	SettingPublicEndpoint = "public_endpoint"
)
