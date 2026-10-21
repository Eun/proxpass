package api

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/proxmox"
)

// Admin handlers for the typed /v1 API.
//
// These implement the administrator half of StrictServerInterface on the
// same *SessionHandler as the session endpoints. They are REST resources
// over db.Repository, the typed counterpart of the hand-written
// /admin/rpc endpoint (adminrpc.go): same authority check, same repository,
// a route per resource instead of one tagged-union endpoint.
//
// Authority is decided here, server-side, from the stored identity -- never
// from anything the request carries. Every handler begins by resolving the
// caller and insisting it is the administrator, exactly as the RPC endpoint
// does, so a client credential reaches none of these writes.

// errNotAdminAPI reports a valid credential that is not the administrator.
//
// Distinct from adminrpc.go's errNotAdmin only so the two endpoints stay
// independent; both turn a non-admin caller into a 403.
var errNotAdminAPI = errors.New("this operation requires the administrator")

// The terse body texts the 400/404 responses carry. Named so the same text
// is not repeated across handlers (goconst) and so a reader sees the whole
// vocabulary in one place.
const (
	errMissingBody    = "request body is required"
	errNoSuchInstance = "no such instance"
	errNoSuchClient   = "no such client"
	errNoSuchGroup    = "no such group"
	errNoSuchGuest    = "no such guest"
	errUnknownSubject = "subject kind must be client or group"
)

// gateAdmin is the authorization preamble every admin handler shares.
//
// It resolves the caller and insists it is the administrator, then turns a
// failure into the handler's own typed response: unauth builds the 401 (from
// the terse missing/invalid reason), forbid builds the 403, and a backend
// failure is returned as an error for the strict server to answer 500. ok is
// true only when the caller is the administrator, in which case denied is the
// zero response and the handler proceeds.
//
// The response type R differs per operation, so the two builders are passed
// in as closures; writing it once here is what keeps 33 handlers from each
// repeating the same switch (which dupl rightly rejects). Authority is
// decided here, server-side, from the stored identity -- never from anything
// the request carries.
func gateAdmin[R any](
	ctx context.Context,
	h *SessionHandler,
	unauth func(reason string) R,
	forbid func() R,
) (denied R, ok bool, err error) {
	identity, err := h.callerIdentity(ctx)
	if err != nil {
		switch {
		case errors.Is(err, errNoCredential):
			return unauth(reasonMissingToken), false, nil
		case errors.Is(err, db.ErrNoSuchToken):
			return unauth(reasonInvalidToken), false, nil
		default:
			var zero R
			return zero, false, err
		}
	}
	if !identity.IsAdmin {
		return forbid(), false, nil
	}
	var zero R
	return zero, true, nil
}

// discoverer is what RunDiscovery uses to poll instances.
//
// Optional: NewSessionHandler leaves it nil so the session endpoints, which
// never discover, pull in nothing. RunDiscovery nil-guards it and answers a
// clear error when discovery was not wired, so a deployment that has not
// configured it fails loudly rather than panicking. Wire it with
// WithDiscoverer during server construction.

// WithDiscoverer wires the discoverer RunDiscovery uses and returns h, so it
// can be chained onto NewSessionHandler without changing that signature.
//
// Append-only on purpose: the session API predates discovery and must keep
// constructing with no discoverer, so this is a setter rather than a new
// required argument.
func (h *SessionHandler) WithDiscoverer(factory proxmox.DiscovererFactory) *SessionHandler {
	h.discoverer = factory
	return h
}

// --- Instances ---

// ListInstances returns every configured Proxmox instance.
//
//nolint:dupl // parallel REST CRUD across entity types; the symmetry is the point
func (h *SessionHandler) ListInstances(
	ctx context.Context, _ ListInstancesRequestObject,
) (ListInstancesResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) ListInstancesResponseObject {
			return ListInstances401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() ListInstancesResponseObject {
			return ListInstances403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	instances, err := h.repo.ListProxmoxInstances(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ProxmoxInstance, 0, len(instances))
	for _, inst := range instances {
		out = append(out, toAPIInstance(inst))
	}
	return ListInstances200JSONResponse(out), nil
}

// AddInstance creates a Proxmox instance.
//
//nolint:dupl // parallel REST CRUD across entity types; the symmetry is the point
func (h *SessionHandler) AddInstance(
	ctx context.Context, request AddInstanceRequestObject,
) (AddInstanceResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) AddInstanceResponseObject {
			return AddInstance401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() AddInstanceResponseObject {
			return AddInstance403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return AddInstance400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	inst := fromAPIInstance(request.Body)
	if err := h.repo.AddProxmoxInstance(ctx, inst); err != nil {
		if isConflict(err) {
			return AddInstance409JSONResponse{ConflictJSONResponse{Error: err.Error()}}, nil
		}
		return nil, err
	}
	return AddInstance201JSONResponse(toAPIInstance(inst)), nil
}

// GetInstance returns one instance by id.
//
// There is no GetByID repo method for instances, so the row is found by
// listing and filtering -- the same way ConnectSessionNode's findInstance
// does. A missing row is a 404.
func (h *SessionHandler) GetInstance(
	ctx context.Context, request GetInstanceRequestObject,
) (GetInstanceResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) GetInstanceResponseObject {
			return GetInstance401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() GetInstanceResponseObject {
			return GetInstance403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	inst, err := h.findInstance(ctx, request.ID)
	if err != nil {
		return nil, err
	}
	if inst == nil {
		return GetInstance404JSONResponse{NotFoundJSONResponse{Error: errNoSuchInstance}}, nil
	}
	return GetInstance200JSONResponse(toAPIInstance(inst)), nil
}

// UpdateInstance replaces an instance by id.
func (h *SessionHandler) UpdateInstance(
	ctx context.Context, request UpdateInstanceRequestObject,
) (UpdateInstanceResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) UpdateInstanceResponseObject {
			return UpdateInstance401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() UpdateInstanceResponseObject {
			return UpdateInstance403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return UpdateInstance400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	existing, err := h.findInstance(ctx, request.ID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return UpdateInstance404JSONResponse{NotFoundJSONResponse{Error: errNoSuchInstance}}, nil
	}
	inst := fromAPIInstance(request.Body)
	inst.ID = request.ID
	if err := h.repo.UpdateProxmoxInstance(ctx, inst); err != nil {
		if isConflict(err) {
			return UpdateInstance409JSONResponse{ConflictJSONResponse{Error: err.Error()}}, nil
		}
		return nil, err
	}
	return UpdateInstance200JSONResponse(toAPIInstance(inst)), nil
}

// RemoveInstance deletes an instance by id.
func (h *SessionHandler) RemoveInstance(
	ctx context.Context, request RemoveInstanceRequestObject,
) (RemoveInstanceResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) RemoveInstanceResponseObject {
			return RemoveInstance401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() RemoveInstanceResponseObject {
			return RemoveInstance403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	existing, err := h.findInstance(ctx, request.ID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return RemoveInstance404JSONResponse{NotFoundJSONResponse{Error: errNoSuchInstance}}, nil
	}
	if err := h.repo.RemoveProxmoxInstance(ctx, request.ID); err != nil {
		return nil, err
	}
	return RemoveInstance204Response{}, nil
}

// --- Clients ---

// ListClients returns every client, or just the one named by ?name=.
//
// The query form uses GetClientByName, which is the only by-name lookup the
// repository offers; a name that matches nothing is a 404 so a caller can
// tell "no such client" from "a client with no rows".
func (h *SessionHandler) ListClients(
	ctx context.Context, request ListClientsRequestObject,
) (ListClientsResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) ListClientsResponseObject {
			return ListClients401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() ListClientsResponseObject {
			return ListClients403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Params.Name != nil {
		client, err := h.repo.GetClientByName(ctx, *request.Params.Name)
		if errors.Is(err, sql.ErrNoRows) {
			return ListClients404JSONResponse{NotFoundJSONResponse{Error: errNoSuchClient}}, nil
		}
		if err != nil {
			return nil, err
		}
		return ListClients200JSONResponse([]AdminClient{toAPIClient(client)}), nil
	}
	clients, err := h.repo.ListClients(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]AdminClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, toAPIClient(c))
	}
	return ListClients200JSONResponse(out), nil
}

// AddClient creates a client.
//
//nolint:dupl // parallel REST CRUD across entity types; the symmetry is the point
func (h *SessionHandler) AddClient(
	ctx context.Context, request AddClientRequestObject,
) (AddClientResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) AddClientResponseObject {
			return AddClient401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() AddClientResponseObject {
			return AddClient403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return AddClient400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	client := fromAPIClient(request.Body)
	if err := h.repo.AddClient(ctx, client); err != nil {
		if isConflict(err) {
			return AddClient409JSONResponse{ConflictJSONResponse{Error: err.Error()}}, nil
		}
		return nil, err
	}
	return AddClient201JSONResponse(toAPIClient(client)), nil
}

// GetClient returns one client by id.
//
// There is no GetByID repo method for clients, so the row is found by
// listing and filtering. GetClientByName exists but keys on name, not id.
func (h *SessionHandler) GetClient(
	ctx context.Context, request GetClientRequestObject,
) (GetClientResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) GetClientResponseObject {
			return GetClient401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() GetClientResponseObject {
			return GetClient403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	client, err := h.findClient(ctx, request.ID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return GetClient404JSONResponse{NotFoundJSONResponse{Error: errNoSuchClient}}, nil
	}
	return GetClient200JSONResponse(toAPIClient(client)), nil
}

// UpdateClient replaces a client by id.
func (h *SessionHandler) UpdateClient(
	ctx context.Context, request UpdateClientRequestObject,
) (UpdateClientResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) UpdateClientResponseObject {
			return UpdateClient401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() UpdateClientResponseObject {
			return UpdateClient403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return UpdateClient400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	existing, err := h.findClient(ctx, request.ID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return UpdateClient404JSONResponse{NotFoundJSONResponse{Error: errNoSuchClient}}, nil
	}
	client := fromAPIClient(request.Body)
	client.ID = request.ID
	if err := h.repo.UpdateClient(ctx, client); err != nil {
		if isConflict(err) {
			return UpdateClient409JSONResponse{ConflictJSONResponse{Error: err.Error()}}, nil
		}
		return nil, err
	}
	return UpdateClient200JSONResponse(toAPIClient(client)), nil
}

// RemoveClient deletes a client by id.
func (h *SessionHandler) RemoveClient(
	ctx context.Context, request RemoveClientRequestObject,
) (RemoveClientResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) RemoveClientResponseObject {
			return RemoveClient401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() RemoveClientResponseObject {
			return RemoveClient403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	existing, err := h.findClient(ctx, request.ID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return RemoveClient404JSONResponse{NotFoundJSONResponse{Error: errNoSuchClient}}, nil
	}
	if err := h.repo.RemoveClient(ctx, request.ID); err != nil {
		return nil, err
	}
	return RemoveClient204Response{}, nil
}

// findClient returns the client with this id, or nil when there is none.
func (h *SessionHandler) findClient(ctx context.Context, id int64) (*models.Client, error) {
	clients, err := h.repo.ListClients(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range clients {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, nil //nolint:nilnil // "no such client" is the caller's to report
}

// --- Groups ---

// ListGroups returns every group.
//
//nolint:dupl // parallel REST CRUD across entity types; the symmetry is the point
func (h *SessionHandler) ListGroups(
	ctx context.Context, _ ListGroupsRequestObject,
) (ListGroupsResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) ListGroupsResponseObject {
			return ListGroups401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() ListGroupsResponseObject {
			return ListGroups403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	groups, err := h.repo.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ClientGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, toAPIGroup(g))
	}
	return ListGroups200JSONResponse(out), nil
}

// AddGroup creates a group.
//
//nolint:dupl // parallel REST CRUD across entity types; the symmetry is the point
func (h *SessionHandler) AddGroup(
	ctx context.Context, request AddGroupRequestObject,
) (AddGroupResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) AddGroupResponseObject {
			return AddGroup401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() AddGroupResponseObject {
			return AddGroup403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return AddGroup400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	group := fromAPIGroup(request.Body)
	if err := h.repo.AddGroup(ctx, group); err != nil {
		if isConflict(err) {
			return AddGroup409JSONResponse{ConflictJSONResponse{Error: err.Error()}}, nil
		}
		return nil, err
	}
	return AddGroup201JSONResponse(toAPIGroup(group)), nil
}

// GetGroup returns one group by id.
//
// There is no GetByID repo method for groups, so the row is found by listing
// and filtering.
func (h *SessionHandler) GetGroup(
	ctx context.Context, request GetGroupRequestObject,
) (GetGroupResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) GetGroupResponseObject {
			return GetGroup401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() GetGroupResponseObject {
			return GetGroup403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	group, err := h.findGroup(ctx, request.ID)
	if err != nil {
		return nil, err
	}
	if group == nil {
		return GetGroup404JSONResponse{NotFoundJSONResponse{Error: errNoSuchGroup}}, nil
	}
	return GetGroup200JSONResponse(toAPIGroup(group)), nil
}

// UpdateGroup replaces a group by id.
func (h *SessionHandler) UpdateGroup(
	ctx context.Context, request UpdateGroupRequestObject,
) (UpdateGroupResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) UpdateGroupResponseObject {
			return UpdateGroup401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() UpdateGroupResponseObject {
			return UpdateGroup403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return UpdateGroup400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	existing, err := h.findGroup(ctx, request.ID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return UpdateGroup404JSONResponse{NotFoundJSONResponse{Error: errNoSuchGroup}}, nil
	}
	group := fromAPIGroup(request.Body)
	group.ID = request.ID
	if err := h.repo.UpdateGroup(ctx, group); err != nil {
		if isConflict(err) {
			return UpdateGroup409JSONResponse{ConflictJSONResponse{Error: err.Error()}}, nil
		}
		return nil, err
	}
	return UpdateGroup200JSONResponse(toAPIGroup(group)), nil
}

// RemoveGroup deletes a group by id.
func (h *SessionHandler) RemoveGroup(
	ctx context.Context, request RemoveGroupRequestObject,
) (RemoveGroupResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) RemoveGroupResponseObject {
			return RemoveGroup401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() RemoveGroupResponseObject {
			return RemoveGroup403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	existing, err := h.findGroup(ctx, request.ID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return RemoveGroup404JSONResponse{NotFoundJSONResponse{Error: errNoSuchGroup}}, nil
	}
	if err := h.repo.RemoveGroup(ctx, request.ID); err != nil {
		return nil, err
	}
	return RemoveGroup204Response{}, nil
}

// findGroup returns the group with this id, or nil when there is none.
func (h *SessionHandler) findGroup(ctx context.Context, id int64) (*models.Group, error) {
	groups, err := h.repo.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.ID == id {
			return g, nil
		}
	}
	return nil, nil //nolint:nilnil // "no such group" is the caller's to report
}

// --- Guests ---

// ListGuests returns every discovered guest.
//
//nolint:dupl // list endpoints share structure across entity types
func (h *SessionHandler) ListGuests(
	ctx context.Context, _ ListGuestsRequestObject,
) (ListGuestsResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) ListGuestsResponseObject {
			return ListGuests401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() ListGuestsResponseObject {
			return ListGuests403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	guests, err := h.repo.ListGuests(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]GuestRow, 0, len(guests))
	for _, g := range guests {
		out = append(out, toAPIGuestRow(g))
	}
	return ListGuests200JSONResponse(out), nil
}

// GetGuest returns one guest by id, using the dedicated GetGuestByID lookup.
func (h *SessionHandler) GetGuest(
	ctx context.Context, request GetGuestRequestObject,
) (GetGuestResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) GetGuestResponseObject {
			return GetGuest401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() GetGuestResponseObject {
			return GetGuest403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	guest, err := h.repo.GetGuestByID(ctx, request.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return GetGuest404JSONResponse{NotFoundJSONResponse{Error: errNoSuchGuest}}, nil
	}
	if err != nil {
		return nil, err
	}
	return GetGuest200JSONResponse(toAPIGuestRow(guest)), nil
}

// --- Access Rules (guests) ---

// ListAccessRules returns every guest access rule, one row per guest.
//
//nolint:dupl // guest and node access handlers are mirror images
func (h *SessionHandler) ListAccessRules(
	ctx context.Context, _ ListAccessRulesRequestObject,
) (ListAccessRulesResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) ListAccessRulesResponseObject {
			return ListAccessRules401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() ListAccessRulesResponseObject {
			return ListAccessRules403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	rules, err := h.repo.ListAccessRules(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]AccessRuleRow, 0, len(rules))
	for _, r := range rules {
		out = append(out, toAPIAccessRuleRow(r))
	}
	return ListAccessRules200JSONResponse(out), nil
}

// GrantAccess grants a client or group access to guests.
//
// The subject's kind selects GrantClientAccess vs GrantGroupAccess; an
// unknown kind is a 400 rather than a silent no-op. The repository takes the
// whole guest-id list at once, so there is no loop here.
func (h *SessionHandler) GrantAccess(
	ctx context.Context, request GrantAccessRequestObject,
) (GrantAccessResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) GrantAccessResponseObject {
			return GrantAccess401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() GrantAccessResponseObject {
			return GrantAccess403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return GrantAccess400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	subject := request.Body.Subject
	guestIDs := request.Body.GuestIds
	switch subject.Kind {
	case RuleTypeClient:
		if err := h.repo.GrantClientAccess(ctx, subject.ID, guestIDs); err != nil {
			return nil, err
		}
	case RuleTypeGroup:
		if err := h.repo.GrantGroupAccess(ctx, subject.ID, guestIDs); err != nil {
			return nil, err
		}
	default:
		return GrantAccess400JSONResponse{BadRequestJSONResponse{Error: errUnknownSubject}}, nil
	}
	return GrantAccess204Response{}, nil
}

// RevokeAccess revokes a client or group's access to guests.
//
// The repository revokes one guest at a time, so this loops over the list;
// as with GrantAccess the subject kind selects client vs group and an
// unknown kind is a 400.
func (h *SessionHandler) RevokeAccess(
	ctx context.Context, request RevokeAccessRequestObject,
) (RevokeAccessResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) RevokeAccessResponseObject {
			return RevokeAccess401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() RevokeAccessResponseObject {
			return RevokeAccess403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return RevokeAccess400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	subject := request.Body.Subject
	switch subject.Kind {
	case RuleTypeClient:
		for _, gid := range request.Body.GuestIds {
			if err := h.repo.RevokeClientAccess(ctx, subject.ID, gid); err != nil {
				return nil, err
			}
		}
	case RuleTypeGroup:
		for _, gid := range request.Body.GuestIds {
			if err := h.repo.RevokeGroupAccess(ctx, subject.ID, gid); err != nil {
				return nil, err
			}
		}
	default:
		return RevokeAccess400JSONResponse{BadRequestJSONResponse{Error: errUnknownSubject}}, nil
	}
	return RevokeAccess204Response{}, nil
}

// --- Instance Access Rules (nodes) ---

// ListInstanceAccessRules returns every node access rule.
//
//nolint:dupl // guest and node access handlers are mirror images
func (h *SessionHandler) ListInstanceAccessRules(
	ctx context.Context, _ ListInstanceAccessRulesRequestObject,
) (ListInstanceAccessRulesResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) ListInstanceAccessRulesResponseObject {
			return ListInstanceAccessRules401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() ListInstanceAccessRulesResponseObject {
			return ListInstanceAccessRules403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	rules, err := h.repo.ListInstanceAccessRules(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]InstanceAccessRuleRow, 0, len(rules))
	for _, r := range rules {
		out = append(out, toAPIInstanceAccessRuleRow(r))
	}
	return ListInstanceAccessRules200JSONResponse(out), nil
}

// GrantInstanceAccess grants a client or group access to Proxmox nodes.
//
// The node counterpart of GrantAccess: subject kind selects client vs group,
// an unknown kind is a 400, and the repository takes the whole instance-id
// list at once.
func (h *SessionHandler) GrantInstanceAccess(
	ctx context.Context, request GrantInstanceAccessRequestObject,
) (GrantInstanceAccessResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) GrantInstanceAccessResponseObject {
			return GrantInstanceAccess401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() GrantInstanceAccessResponseObject {
			return GrantInstanceAccess403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return GrantInstanceAccess400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	subject := request.Body.Subject
	instanceIDs := request.Body.InstanceIds
	switch subject.Kind {
	case RuleTypeClient:
		if err := h.repo.GrantClientInstanceAccess(ctx, subject.ID, instanceIDs); err != nil {
			return nil, err
		}
	case RuleTypeGroup:
		if err := h.repo.GrantGroupInstanceAccess(ctx, subject.ID, instanceIDs); err != nil {
			return nil, err
		}
	default:
		return GrantInstanceAccess400JSONResponse{BadRequestJSONResponse{Error: errUnknownSubject}}, nil
	}
	return GrantInstanceAccess204Response{}, nil
}

// RevokeInstanceAccess revokes a client or group's access to nodes.
//
// The repository revokes one instance at a time, so this loops; subject kind
// selects client vs group and an unknown kind is a 400.
func (h *SessionHandler) RevokeInstanceAccess(
	ctx context.Context, request RevokeInstanceAccessRequestObject,
) (RevokeInstanceAccessResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) RevokeInstanceAccessResponseObject {
			return RevokeInstanceAccess401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() RevokeInstanceAccessResponseObject {
			return RevokeInstanceAccess403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return RevokeInstanceAccess400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	subject := request.Body.Subject
	switch subject.Kind {
	case RuleTypeClient:
		for _, iid := range request.Body.InstanceIds {
			if err := h.repo.RevokeClientInstanceAccess(ctx, subject.ID, iid); err != nil {
				return nil, err
			}
		}
	case RuleTypeGroup:
		for _, iid := range request.Body.InstanceIds {
			if err := h.repo.RevokeGroupInstanceAccess(ctx, subject.ID, iid); err != nil {
				return nil, err
			}
		}
	default:
		return RevokeInstanceAccess400JSONResponse{BadRequestJSONResponse{Error: errUnknownSubject}}, nil
	}
	return RevokeInstanceAccess204Response{}, nil
}

// --- Default Policy ---

// GetDefaultPolicy returns the fallback access policy.
func (h *SessionHandler) GetDefaultPolicy(
	ctx context.Context, _ GetDefaultPolicyRequestObject,
) (GetDefaultPolicyResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) GetDefaultPolicyResponseObject {
			return GetDefaultPolicy401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() GetDefaultPolicyResponseObject {
			return GetDefaultPolicy403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	policy, err := h.repo.GetDefaultPolicy(ctx)
	if err != nil {
		return nil, err
	}
	return GetDefaultPolicy200JSONResponse(toAPIDefaultPolicy(policy)), nil
}

// SetDefaultPolicy replaces the fallback access policy.
func (h *SessionHandler) SetDefaultPolicy(
	ctx context.Context, request SetDefaultPolicyRequestObject,
) (SetDefaultPolicyResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) SetDefaultPolicyResponseObject {
			return SetDefaultPolicy401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() SetDefaultPolicyResponseObject {
			return SetDefaultPolicy403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return SetDefaultPolicy400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	policy := fromAPIDefaultPolicy(request.Body)
	if err := h.repo.SetDefaultPolicy(ctx, policy); err != nil {
		return nil, err
	}
	return SetDefaultPolicy200JSONResponse(toAPIDefaultPolicy(policy)), nil
}

// --- Settings ---

// GetSetting returns one setting by key.
//
// An unset key reads back as "" from the repository, which is a legitimate
// value rather than an error, so this answers 200 with an empty value. The
// generated 404 is kept for keys the spec may later restrict, but the
// current store has no notion of "no such key".
func (h *SessionHandler) GetSetting(
	ctx context.Context, request GetSettingRequestObject,
) (GetSettingResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) GetSettingResponseObject {
			return GetSetting401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() GetSettingResponseObject {
			return GetSetting403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	value, err := h.repo.GetSetting(ctx, request.Key)
	if err != nil {
		return nil, err
	}
	return GetSetting200JSONResponse(Setting{Key: request.Key, Value: value}), nil
}

// SetSetting stores a setting value under key.
func (h *SessionHandler) SetSetting(
	ctx context.Context, request SetSettingRequestObject,
) (SetSettingResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) SetSettingResponseObject {
			return SetSetting401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() SetSettingResponseObject {
			return SetSetting403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return SetSetting400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	if err := h.repo.SetSetting(ctx, request.Key, request.Body.Value); err != nil {
		return nil, err
	}
	return SetSetting200JSONResponse(Setting{Key: request.Key, Value: request.Body.Value}), nil
}

// --- Admin Keys ---

// ListAdminKeys returns every administrator public key.
func (h *SessionHandler) ListAdminKeys(
	ctx context.Context, _ ListAdminKeysRequestObject,
) (ListAdminKeysResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) ListAdminKeysResponseObject {
			return ListAdminKeys401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() ListAdminKeysResponseObject {
			return ListAdminKeys403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	keys, err := h.repo.ListAdminKeys(ctx)
	if err != nil {
		return nil, err
	}
	return ListAdminKeys200JSONResponse(AdminKeyList{PublicKeys: nonNilStrings(keys)}), nil
}

// AddAdminKey adds an administrator public key.
func (h *SessionHandler) AddAdminKey(
	ctx context.Context, request AddAdminKeyRequestObject,
) (AddAdminKeyResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) AddAdminKeyResponseObject {
			return AddAdminKey401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() AddAdminKeyResponseObject {
			return AddAdminKey403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return AddAdminKey400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	if err := h.repo.AddAdminKey(ctx, request.Body.PublicKey); err != nil {
		if isConflict(err) {
			return AddAdminKey409JSONResponse{ConflictJSONResponse{Error: err.Error()}}, nil
		}
		return nil, err
	}
	return AddAdminKey204Response{}, nil
}

// RemoveAdminKey removes an administrator public key.
func (h *SessionHandler) RemoveAdminKey(
	ctx context.Context, request RemoveAdminKeyRequestObject,
) (RemoveAdminKeyResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) RemoveAdminKeyResponseObject {
			return RemoveAdminKey401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() RemoveAdminKeyResponseObject {
			return RemoveAdminKey403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if request.Body == nil {
		return RemoveAdminKey400JSONResponse{BadRequestJSONResponse{Error: errMissingBody}}, nil
	}
	// The configured admin key (PROXPASS_ADMIN_KEY) cannot be removed here:
	// serve re-adds it on the next start, so "deleting" it would only lock the
	// configured administrator out until a restart quietly restored it. Refuse
	// with a 409 and a message the UI can show, rather than accept a delete
	// that does not stick.
	if h.protectedAdminKey != "" &&
		strings.TrimSpace(request.Body.PublicKey) == h.protectedAdminKey {
		return RemoveAdminKey409JSONResponse{ConflictJSONResponse{
			Error: "this key is set by PROXPASS_ADMIN_KEY and cannot be removed " +
				"here; change the configuration and restart instead",
		}}, nil
	}
	if err := h.repo.RemoveAdminKey(ctx, request.Body.PublicKey); err != nil {
		return nil, err
	}
	return RemoveAdminKey204Response{}, nil
}

// --- Discovery ---

// RunDiscovery polls Proxmox instances for their guests now.
//
// It mirrors the `proxpass discover` CLI command and the background
// discovery loop: for each instance it discovers guests and stores the
// running ones, pruning anything stale, and reports per-instance counts. A
// single instance's failure is recorded in its row and the pass continues,
// so one unreachable node does not fail the whole call.
//
// ?instance=<id> narrows the pass to one instance; an id that matches
// nothing is a 404.
//
// The discoverer is optional (see the field): a deployment that has not
// wired one gets a clear error here rather than a panic. There is no 503 in
// the generated responses, so an unconfigured discoverer surfaces as a 500
// with an explanatory message.
func (h *SessionHandler) RunDiscovery(
	ctx context.Context, request RunDiscoveryRequestObject,
) (RunDiscoveryResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) RunDiscoveryResponseObject {
			return RunDiscovery401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() RunDiscoveryResponseObject {
			return RunDiscovery403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}
	if h.discoverer == nil {
		return nil, errors.New(
			"discovery is not configured on this server: wire a discoverer with WithDiscoverer")
	}

	instances, err := h.repo.ListProxmoxInstances(ctx)
	if err != nil {
		return nil, err
	}
	if request.Params.Instance != nil {
		instances = filterInstancesByID(instances, *request.Params.Instance)
		if len(instances) == 0 {
			return RunDiscovery404JSONResponse{NotFoundJSONResponse{Error: errNoSuchInstance}}, nil
		}
	}

	result := DiscoverResult{Instances: make([]DiscoverInstanceResult, 0, len(instances))}
	for _, inst := range instances {
		row := h.discoverInstance(ctx, inst)
		result.Total += row.Stored
		result.Instances = append(result.Instances, row)
	}
	return RunDiscovery200JSONResponse(result), nil
}

// discoverInstance runs one instance's discovery pass and reports its counts.
//
// A discovery or store failure is recorded on the row's Error and the pass
// moves on, exactly as the CLI and background loop do: one bad instance must
// not fail the others.
func (h *SessionHandler) discoverInstance(
	ctx context.Context, inst *models.ProxmoxInstance,
) DiscoverInstanceResult {
	row := DiscoverInstanceResult{InstanceID: inst.ID, Name: inst.Name}

	guests, err := h.discoverer(inst).DiscoverGuests(ctx)
	if err != nil {
		msg := err.Error()
		row.Error = &msg
		return row
	}
	row.Discovered = len(guests)

	stored, removed, err := proxmox.StoreGuests(ctx, h.repo, inst, guests)
	if err != nil {
		msg := err.Error()
		row.Error = &msg
		return row
	}
	row.Stored = stored
	row.Removed = removed
	return row
}

// filterInstancesByID returns the instance with id, or an empty slice.
func filterInstancesByID(
	instances []*models.ProxmoxInstance, id int64,
) []*models.ProxmoxInstance {
	for _, inst := range instances {
		if inst.ID == id {
			return []*models.ProxmoxInstance{inst}
		}
	}
	return nil
}
