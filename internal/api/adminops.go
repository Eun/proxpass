package api

import (
	"context"
	"encoding/json"

	"proxpass/internal/db"
	"proxpass/internal/models"
)

// adminOp performs one Repository call from its JSON arguments.
type adminOp func(ctx context.Context, repo db.Repository, params json.RawMessage) (json.RawMessage, error)

// adminOps is the allowlist.
//
// Exactly the methods the admin CLI uses, and nothing else: a Repository
// method that is not here cannot be reached, so adding one to the interface
// does not quietly widen what an administrator can do over the wire. The
// names match the Go methods so that a reader can check the two against each
// other without a mapping table.
//
// The session's own methods are deliberately ABSENT. MintSessionToken,
// CreateAPISession and the rest are how authentication works; exposing them
// here would let an administrator -- or anything that got hold of an admin
// credential -- mint a credential for somebody else and bypass the key check
// entirely.
var adminOps = map[string]adminOp{
	// --- Proxmox instances ---
	"AddProxmoxInstance": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			Instance *models.ProxmoxInstance `json:"instance"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		if err := repo.AddProxmoxInstance(ctx, args.Instance); err != nil {
			return nil, err
		}
		// The id is assigned by the database, and the caller needs it.
		return encodeResult(args.Instance)
	},
	"ListProxmoxInstances": func(ctx context.Context, repo db.Repository, _ json.RawMessage) (json.RawMessage, error) {
		out, err := repo.ListProxmoxInstances(ctx)
		if err != nil {
			return nil, err
		}
		return encodeResult(out)
	},
	"UpdateProxmoxInstance": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			Instance *models.ProxmoxInstance `json:"instance"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		if err := repo.UpdateProxmoxInstance(ctx, args.Instance); err != nil {
			return nil, err
		}
		return encodeResult(args.Instance)
	},
	"RemoveProxmoxInstance": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			ID int64 `json:"id"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.RemoveProxmoxInstance(ctx, args.ID)
	},

	// --- Guests ---
	"UpsertGuest": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			Guest *models.Guest `json:"guest"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.UpsertGuest(ctx, args.Guest)
	},
	"ListGuests": func(ctx context.Context, repo db.Repository, _ json.RawMessage) (json.RawMessage, error) {
		out, err := repo.ListGuests(ctx)
		if err != nil {
			return nil, err
		}
		return encodeResult(out)
	},
	"RemoveGuestsNotIn": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			InstanceID int64 `json:"instance_id"`
			Keep       []int `json:"keep"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		n, err := repo.RemoveGuestsNotIn(ctx, args.InstanceID, args.Keep)
		if err != nil {
			return nil, err
		}
		return encodeResult(n)
	},

	// --- Clients ---
	"AddClient": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			Client *models.Client `json:"client"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		if err := repo.AddClient(ctx, args.Client); err != nil {
			return nil, err
		}
		return encodeResult(args.Client)
	},
	"ListClients": func(ctx context.Context, repo db.Repository, _ json.RawMessage) (json.RawMessage, error) {
		out, err := repo.ListClients(ctx)
		if err != nil {
			return nil, err
		}
		return encodeResult(out)
	},
	"RemoveClient": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			ID int64 `json:"id"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.RemoveClient(ctx, args.ID)
	},
	"GetClientByName": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			Name string `json:"name"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		out, err := repo.GetClientByName(ctx, args.Name)
		if err != nil {
			return nil, err
		}
		return encodeResult(out)
	},

	// --- Groups ---
	"AddGroup": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			Group *models.Group `json:"group"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		if err := repo.AddGroup(ctx, args.Group); err != nil {
			return nil, err
		}
		return encodeResult(args.Group)
	},
	"ListGroups": func(ctx context.Context, repo db.Repository, _ json.RawMessage) (json.RawMessage, error) {
		out, err := repo.ListGroups(ctx)
		if err != nil {
			return nil, err
		}
		return encodeResult(out)
	},
	"RemoveGroup": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			ID int64 `json:"id"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.RemoveGroup(ctx, args.ID)
	},

	// --- Access rules ---
	"ListAccessRules": func(ctx context.Context, repo db.Repository, _ json.RawMessage) (json.RawMessage, error) {
		out, err := repo.ListAccessRules(ctx)
		if err != nil {
			return nil, err
		}
		return encodeResult(out)
	},
	"GrantClientAccess": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			ClientID int64   `json:"client_id"`
			GuestIDs []int64 `json:"guest_ids"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.GrantClientAccess(ctx, args.ClientID, args.GuestIDs)
	},
	"GrantGroupAccess": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			GroupID  int64   `json:"group_id"`
			GuestIDs []int64 `json:"guest_ids"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.GrantGroupAccess(ctx, args.GroupID, args.GuestIDs)
	},
	"RevokeClientAccess": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			ClientID int64 `json:"client_id"`
			GuestID  int64 `json:"guest_id"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.RevokeClientAccess(ctx, args.ClientID, args.GuestID)
	},
	"RevokeGroupAccess": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			GroupID int64 `json:"group_id"`
			GuestID int64 `json:"guest_id"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.RevokeGroupAccess(ctx, args.GroupID, args.GuestID)
	},

	// --- Default policy ---
	"GetDefaultPolicy": func(ctx context.Context, repo db.Repository, _ json.RawMessage) (json.RawMessage, error) {
		out, err := repo.GetDefaultPolicy(ctx)
		if err != nil {
			return nil, err
		}
		return encodeResult(out)
	},
	"SetDefaultPolicy": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			Policy *models.DefaultAccessPolicy `json:"policy"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.SetDefaultPolicy(ctx, args.Policy)
	},

	// --- Admin keys ---
	"AddAdminKey": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			PublicKey string `json:"public_key"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.AddAdminKey(ctx, args.PublicKey)
	},
	"ListAdminKeys": func(ctx context.Context, repo db.Repository, _ json.RawMessage) (json.RawMessage, error) {
		out, err := repo.ListAdminKeys(ctx)
		if err != nil {
			return nil, err
		}
		return encodeResult(out)
	},
	"RemoveAdminKey": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			PublicKey string `json:"public_key"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.RemoveAdminKey(ctx, args.PublicKey)
	},

	// --- Settings ---
	//
	// Readable and writable because `instance add' records the public
	// endpoint, and the status bar reads it. Not a credential.
	"GetSetting": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			Key string `json:"key"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		out, err := repo.GetSetting(ctx, args.Key)
		if err != nil {
			return nil, err
		}
		return encodeResult(out)
	},
	"SetSetting": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		return nil, repo.SetSetting(ctx, args.Key, args.Value)
	},

	// --- Access check ---
	"HasAccess": func(ctx context.Context, repo db.Repository, p json.RawMessage) (json.RawMessage, error) {
		var args struct {
			ClientID int64 `json:"client_id"`
			GuestID  int64 `json:"guest_id"`
		}
		if err := decodeParams(p, &args); err != nil {
			return nil, err
		}
		out, err := repo.HasAccess(ctx, args.ClientID, args.GuestID)
		if err != nil {
			return nil, err
		}
		return encodeResult(out)
	},
}

func decodeParams(p json.RawMessage, into any) error {
	if len(p) == 0 {
		return nil
	}
	return json.Unmarshal(p, into)
}

func encodeResult(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}
