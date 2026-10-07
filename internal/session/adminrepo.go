package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"proxpass/internal/api"
	"proxpass/internal/db"
	"proxpass/internal/models"
)

// AdminRepository is a db.Repository served by the loopback API.
//
// The admin CLI is a large surface -- 21 commands over 23 repository methods
// -- and every one of them already speaks this interface. Implementing the
// interface rather than rewriting the CLI means the commands are untouched,
// so this change moves WHERE the data lives without altering what any
// command does. That is the only version of this change that can be reviewed
// with confidence.
//
// Only the methods the admin CLI actually uses are implemented. The rest
// panic, loudly and on purpose: they are unreachable from an admin session,
// and a silent zero value would be a correctness bug waiting to happen. See
// unsupported.
type AdminRepository struct {
	client *APIClient
}

// NewAdminRepository returns a repository backed by the admin API.
func NewAdminRepository(client *APIClient) *AdminRepository {
	return &AdminRepository{client: client}
}

// call performs one operation and decodes its result.
func (r *AdminRepository) call(
	ctx context.Context, op string, params, result any,
) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("encoding %s: %w", op, err)
		}
		raw = b
	}

	var resp api.AdminResponse
	if err := r.client.postJSON(ctx, "/admin/rpc",
		api.AdminRequest{Op: op, Params: raw}, &resp); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if resp.Error != "" {
		// The server passes the repository's own error through, so the CLI
		// prints what it always printed.
		return errors.New(resp.Error)
	}
	if result == nil || len(resp.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(resp.Result, result); err != nil {
		return fmt.Errorf("decoding %s: %w", op, err)
	}
	return nil
}

// Close is a no-op: there is no handle to close.
func (r *AdminRepository) Close() error { return nil }

// JSON parameter names that appear in several operations.
const (
	keyID        = "id"
	keyPublicKey = "public_key"
	keyClientID  = "client_id"
	keyGuestID   = "guest_id"
)

// --- Proxmox instances ---

func (r *AdminRepository) AddProxmoxInstance(ctx context.Context, inst *models.ProxmoxInstance) error {
	// The database assigns the id, so the stored row comes back and is
	// copied over the caller's struct -- the CLI reads inst.ID afterwards.
	var out models.ProxmoxInstance
	if err := r.call(ctx, "AddProxmoxInstance",
		map[string]any{"instance": inst}, &out); err != nil {
		return err
	}
	*inst = out
	return nil
}

func (r *AdminRepository) ListProxmoxInstances(ctx context.Context) ([]*models.ProxmoxInstance, error) {
	var out []*models.ProxmoxInstance
	if err := r.call(ctx, "ListProxmoxInstances", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *AdminRepository) RemoveProxmoxInstance(ctx context.Context, id int64) error {
	return r.call(ctx, "RemoveProxmoxInstance", map[string]any{keyID: id}, nil)
}

// --- Guests ---

func (r *AdminRepository) UpsertGuest(ctx context.Context, guest *models.Guest) error {
	return r.call(ctx, "UpsertGuest", map[string]any{"guest": guest}, nil)
}

func (r *AdminRepository) ListGuests(ctx context.Context) ([]*models.Guest, error) {
	var out []*models.Guest
	if err := r.call(ctx, "ListGuests", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *AdminRepository) RemoveGuestsNotIn(ctx context.Context, instanceID int64, keep []int) (int, error) {
	var n int
	if err := r.call(ctx, "RemoveGuestsNotIn",
		map[string]any{"instance_id": instanceID, "keep": keep}, &n); err != nil {
		return 0, err
	}
	return n, nil
}

// --- Clients ---

func (r *AdminRepository) AddClient(ctx context.Context, client *models.Client) error {
	var out models.Client
	if err := r.call(ctx, "AddClient",
		map[string]any{"client": client}, &out); err != nil {
		return err
	}
	*client = out
	return nil
}

func (r *AdminRepository) ListClients(ctx context.Context) ([]*models.Client, error) {
	var out []*models.Client
	if err := r.call(ctx, "ListClients", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *AdminRepository) RemoveClient(ctx context.Context, id int64) error {
	return r.call(ctx, "RemoveClient", map[string]any{keyID: id}, nil)
}

func (r *AdminRepository) GetClientByName(ctx context.Context, name string) (*models.Client, error) {
	var out *models.Client
	if err := r.call(ctx, "GetClientByName",
		map[string]any{"name": name}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- Groups ---

func (r *AdminRepository) AddGroup(ctx context.Context, group *models.Group) error {
	var out models.Group
	if err := r.call(ctx, "AddGroup",
		map[string]any{"group": group}, &out); err != nil {
		return err
	}
	*group = out
	return nil
}

func (r *AdminRepository) ListGroups(ctx context.Context) ([]*models.Group, error) {
	var out []*models.Group
	if err := r.call(ctx, "ListGroups", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *AdminRepository) RemoveGroup(ctx context.Context, id int64) error {
	return r.call(ctx, "RemoveGroup", map[string]any{keyID: id}, nil)
}

// --- Access rules ---

func (r *AdminRepository) ListAccessRules(ctx context.Context) ([]*models.AccessRuleRow, error) {
	var out []*models.AccessRuleRow
	if err := r.call(ctx, "ListAccessRules", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *AdminRepository) GrantClientAccess(ctx context.Context, clientID int64, guestIDs []int64) error {
	return r.call(ctx, "GrantClientAccess",
		map[string]any{keyClientID: clientID, "guest_ids": guestIDs}, nil)
}

func (r *AdminRepository) GrantGroupAccess(ctx context.Context, groupID int64, guestIDs []int64) error {
	return r.call(ctx, "GrantGroupAccess",
		map[string]any{"group_id": groupID, "guest_ids": guestIDs}, nil)
}

func (r *AdminRepository) RevokeClientAccess(ctx context.Context, clientID, guestID int64) error {
	return r.call(ctx, "RevokeClientAccess",
		map[string]any{keyClientID: clientID, keyGuestID: guestID}, nil)
}

func (r *AdminRepository) RevokeGroupAccess(ctx context.Context, groupID, guestID int64) error {
	return r.call(ctx, "RevokeGroupAccess",
		map[string]any{"group_id": groupID, "guest_id": guestID}, nil)
}

// --- Default policy ---

func (r *AdminRepository) SetDefaultPolicy(ctx context.Context, policy *models.DefaultAccessPolicy) error {
	return r.call(ctx, "SetDefaultPolicy", map[string]any{"policy": policy}, nil)
}

func (r *AdminRepository) GetDefaultPolicy(ctx context.Context) (*models.DefaultAccessPolicy, error) {
	var out *models.DefaultAccessPolicy
	if err := r.call(ctx, "GetDefaultPolicy", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- Settings ---

func (r *AdminRepository) SetSetting(ctx context.Context, key, value string) error {
	return r.call(ctx, "SetSetting",
		map[string]any{"key": key, "value": value}, nil)
}

func (r *AdminRepository) GetSetting(ctx context.Context, key string) (string, error) {
	var out string
	if err := r.call(ctx, "GetSetting", map[string]any{"key": key}, &out); err != nil {
		return "", err
	}
	return out, nil
}

// --- Admin keys ---

func (r *AdminRepository) AddAdminKey(ctx context.Context, pubKey string) error {
	return r.call(ctx, "AddAdminKey", map[string]any{keyPublicKey: pubKey}, nil)
}

func (r *AdminRepository) ListAdminKeys(ctx context.Context) ([]string, error) {
	var out []string
	if err := r.call(ctx, "ListAdminKeys", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *AdminRepository) RemoveAdminKey(ctx context.Context, pubKey string) error {
	return r.call(ctx, "RemoveAdminKey", map[string]any{keyPublicKey: pubKey}, nil)
}

// --- Access check ---

func (r *AdminRepository) HasAccess(ctx context.Context, clientID, guestID int64) (bool, error) {
	// Call first, then return, rather than `return out, r.call(..., &out)'.
	//
	// Both are correct -- Go finishes the call before reading out -- but the
	// one-liner reads as though it might not, which is why gocritic flags
	// it. Checked against the compiler before settling on this: the
	// one-liner does return the filled value.
	var out bool
	if err := r.call(ctx, "HasAccess",
		map[string]any{keyClientID: clientID, keyGuestID: guestID}, &out); err != nil {
		return false, err
	}
	return out, nil
}

// --- Not reachable from a session ---
//
// These exist only to satisfy db.Repository. A session never calls them: the
// guest lookup is served by the Directory, and the token methods belong to
// `proxpass serve', which holds the real database. They panic rather than
// return a zero value, so a future caller finds out immediately instead of
// silently getting "no such row" or a token that was never stored.

func (r *AdminRepository) GetGuestByID(context.Context, int64) (*models.Guest, error) {
	panic(unsupported("GetGuestByID"))
}

func (r *AdminRepository) UpdateProxmoxInstance(ctx context.Context, inst *models.ProxmoxInstance) error {
	// The stored row comes back and is copied over the caller's struct, so
	// that a field the server normalized -- the API URL loses a trailing
	// slash -- is what the caller then prints.
	var out models.ProxmoxInstance
	if err := r.call(ctx, "UpdateProxmoxInstance",
		map[string]any{"instance": inst}, &out); err != nil {
		return err
	}
	*inst = out
	return nil
}

func (r *AdminRepository) UpdateClient(context.Context, *models.Client) error {
	panic(unsupported("UpdateClient"))
}

func (r *AdminRepository) UpdateGroup(context.Context, *models.Group) error {
	panic(unsupported("UpdateGroup"))
}

func (r *AdminRepository) MintSessionToken(
	context.Context, string, *models.SessionIdentity, time.Time, time.Time,
) error {
	panic(unsupported("MintSessionToken"))
}

func (r *AdminRepository) RedeemSessionToken(
	context.Context, string, time.Time,
) (*models.SessionIdentity, error) {
	panic(unsupported("RedeemSessionToken"))
}

func (r *AdminRepository) CreateAPISession(
	context.Context, string, *models.SessionIdentity, time.Time, time.Time,
) error {
	panic(unsupported("CreateAPISession"))
}

func (r *AdminRepository) LookupAPISession(
	context.Context, string, time.Time,
) (*models.SessionIdentity, error) {
	panic(unsupported("LookupAPISession"))
}

func (r *AdminRepository) RevokeAPISession(context.Context, string) error {
	panic(unsupported("RevokeAPISession"))
}

// unsupported explains why a method is missing rather than just that it is.
func unsupported(method string) string {
	return "session: " + method + " is not available over the admin API; " +
		"a session does not hold the database, and this method is not one " +
		"the admin CLI uses"
}

// AdminRepository must satisfy the interface the CLI takes.
var _ db.Repository = (*AdminRepository)(nil)
