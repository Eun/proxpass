package db

import (
	"context"

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

	// Admin Keys
	AddAdminKey(ctx context.Context, pubKey string) error
	ListAdminKeys(ctx context.Context) ([]string, error)
	RemoveAdminKey(ctx context.Context, pubKey string) error

	// Access check (used by the proxy)
	HasAccess(ctx context.Context, clientID, guestID int64) (bool, error)
}
