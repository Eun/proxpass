package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"proxpass/internal/api"
	"proxpass/internal/db"
	"proxpass/internal/models"
)

// ErrAccessDenied reports a guest this session may not reach.
//
// It is also what a guest that does not exist produces, deliberately:
// telling the two apart would let a caller map the cluster by trying ids.
var ErrAccessDenied = errors.New("access denied")

// RepoDirectory serves a session straight from the database.
//
// This is what an administrator uses. An admin session is privileged by
// design -- it can run the full admin CLI, which writes -- so routing its
// reads through the API would buy nothing.
type RepoDirectory struct {
	Repo     db.Repository
	IsAdmin  bool
	ClientID int64
}

// AccessibleGuests returns the guests this session may reach.
func (d *RepoDirectory) AccessibleGuests(ctx context.Context) ([]*GuestInfo, error) {
	guests, err := d.Repo.ListGuests(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing guests: %w", err)
	}
	instances, err := d.Repo.ListProxmoxInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing instances: %w", err)
	}
	names := make(map[int64]string, len(instances))
	for _, inst := range instances {
		names[inst.ID] = inst.Name
	}

	out := make([]*GuestInfo, 0, len(guests))
	for _, g := range guests {
		if !d.IsAdmin {
			ok, err := d.Repo.HasAccess(ctx, d.ClientID, g.ID)
			if err != nil {
				return nil, fmt.Errorf("checking access: %w", err)
			}
			if !ok {
				continue
			}
		}
		out = append(out, &GuestInfo{Guest: g, InstanceName: names[g.InstanceID]})
	}
	return out, nil
}

// Connect returns the credentials for one guest's instance.
func (d *RepoDirectory) Connect(ctx context.Context, guestID int64) (*ConnectInfo, error) {
	guest, err := d.Repo.GetGuestByID(ctx, guestID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAccessDenied
	}
	if err != nil {
		return nil, fmt.Errorf("looking up guest: %w", err)
	}

	if !d.IsAdmin {
		ok, err := d.Repo.HasAccess(ctx, d.ClientID, guest.ID)
		if err != nil {
			return nil, fmt.Errorf("checking access: %w", err)
		}
		if !ok {
			return nil, ErrAccessDenied
		}
	}

	instances, err := d.Repo.ListProxmoxInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing instances: %w", err)
	}
	for _, inst := range instances {
		if inst.ID == guest.InstanceID {
			return &ConnectInfo{Guest: guest, Instance: inst}, nil
		}
	}
	return nil, fmt.Errorf("guest %d references missing instance %d",
		guest.ID, guest.InstanceID)
}

// IsLoginNameReserved reports whether a login name means "browse".
func (d *RepoDirectory) IsLoginNameReserved(ctx context.Context, name string) (bool, error) {
	if strings.EqualFold(name, AdminUser) {
		return true, nil
	}
	clients, err := d.Repo.ListClients(ctx)
	if err != nil {
		return false, fmt.Errorf("listing clients: %w", err)
	}
	for _, c := range clients {
		if strings.EqualFold(c.Name, name) {
			return true, nil
		}
	}
	return false, nil
}

// PublicEndpoint returns the configured endpoint, or "" when unset.
func (d *RepoDirectory) PublicEndpoint(ctx context.Context) (string, error) {
	return d.Repo.GetSetting(ctx, db.SettingPublicEndpoint)
}

// guestFromAPI converts a wire guest back into the model the console and
// CLI already take.
func guestFromAPI(g *api.Guest) *models.Guest {
	return &models.Guest{
		ID:         g.ID,
		Type:       models.GuestType(g.Type),
		Name:       g.Name,
		Status:     models.Status(g.Status),
		ProxmoxID:  g.ProxmoxID,
		InstanceID: g.InstanceID,
	}
}

// instanceFromAPI converts wire credentials back into the model.
//
// The pointer fields are absent rather than empty when an instance does not
// use them -- an SSH instance has no API token -- so each is dereferenced
// only when present.
func instanceFromAPI(c *api.InstanceCredentials) *models.ProxmoxInstance {
	inst := &models.ProxmoxInstance{
		ID:             c.ID,
		Name:           c.Name,
		APIURL:         c.APIURL,
		ConnectionType: models.ConnectionType(c.ConnectionType),
		Node:           c.Node,
	}
	if c.APITokenID != nil {
		inst.APITokenID = *c.APITokenID
	}
	if c.APITokenSecret != nil {
		inst.APITokenSecret = *c.APITokenSecret
	}
	if c.SSHHost != nil {
		inst.SSHHost = *c.SSHHost
	}
	if c.SSHPort != nil {
		inst.SSHPort = *c.SSHPort
	}
	if c.SSHUser != nil {
		inst.SSHUser = *c.SSHUser
	}
	// Always inline: the server resolved a configured key PATH by reading
	// the file, because this process cannot. SSHKeyPath is deliberately
	// left empty so nothing downstream tries to open it.
	if c.SSHKey != nil {
		inst.SSHKey = *c.SSHKey
	}
	return inst
}
