package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"proxpass/internal/db"
	"proxpass/internal/models"
)

// ListSessionGuests returns the guests the caller may reach.
//
// The filtering is the point: a caller that may not reach a guest does not
// see it, rather than seeing it and being refused later. Scope comes from
// the stored identity, never from the request.
func (h *SessionHandler) ListSessionGuests(
	ctx context.Context, _ ListSessionGuestsRequestObject,
) (ListSessionGuestsResponseObject, error) {
	identity, err := h.callerIdentity(ctx)
	if err != nil {
		return listGuestsAuthFailure(err)
	}

	guests, err := h.accessibleGuests(ctx, identity)
	if err != nil {
		return nil, err
	}
	names, err := h.instanceNames(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]Guest, 0, len(guests))
	for _, g := range guests {
		out = append(out, guestResponse(g, names[g.InstanceID]))
	}
	return ListSessionGuests200JSONResponse(out), nil
}

// ConnectSessionGuest hands over the credentials for one guest's instance.
//
// The access check happens HERE, from the stored identity. Being able to
// name a guest is not permission to reach it: a caller could have learned
// the id anywhere, and the list endpoint having filtered is not something
// this endpoint may assume.
func (h *SessionHandler) ConnectSessionGuest(
	ctx context.Context, request ConnectSessionGuestRequestObject,
) (ConnectSessionGuestResponseObject, error) {
	identity, err := h.callerIdentity(ctx)
	if err != nil {
		reason := authFailureReason(err)
		if reason == "" {
			return nil, err
		}
		return ConnectSessionGuest401JSONResponse{
			UnauthorizedJSONResponse: UnauthorizedJSONResponse{Error: reason},
		}, nil
	}

	guest, err := h.findGuest(ctx, request.GuestID)
	if err != nil {
		return nil, err
	}
	// A guest that does not exist and a guest the caller may not reach get
	// the same answer. Distinguishing them would let a client discover what
	// the cluster contains by trying ids.
	if guest == nil {
		return forbidden(), nil
	}
	allowed, err := h.mayReach(ctx, identity, guest.ID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return forbidden(), nil
	}

	inst, err := h.findInstance(ctx, guest.InstanceID)
	if err != nil {
		return nil, err
	}
	if inst == nil {
		// The guest exists but its instance has gone. Not a permission
		// problem, and not something the caller can act on.
		return nil, fmt.Errorf("guest %d references missing instance %d",
			guest.ID, guest.InstanceID)
	}

	credentials, err := h.instanceCredentials(inst)
	if err != nil {
		return nil, err
	}
	return ConnectSessionGuest200JSONResponse(ConnectInfo{
		Guest:    guestResponse(guest, inst.Name),
		Instance: credentials,
	}), nil
}

// IsLoginNameReserved reports whether a login name means "browse".
//
// Answers about one name rather than returning the list: the caller already
// knows the name it is asking about, so this discloses nothing, while the
// list would tell every client who else exists.
func (h *SessionHandler) IsLoginNameReserved(
	ctx context.Context, request IsLoginNameReservedRequestObject,
) (IsLoginNameReservedResponseObject, error) {
	if _, err := h.callerIdentity(ctx); err != nil {
		return reservedAuthFailure(err)
	}

	name := request.Params.Name
	if strings.EqualFold(name, AdminUser) {
		return IsLoginNameReserved200JSONResponse{Reserved: true}, nil
	}

	// Every configured client name is reserved, not only the caller's own:
	// what a name means must not depend on who is asking, or the same
	// command would do different things for different callers.
	clients, err := h.repo.ListClients(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range clients {
		if strings.EqualFold(c.Name, name) {
			return IsLoginNameReserved200JSONResponse{Reserved: true}, nil
		}
	}
	return IsLoginNameReserved200JSONResponse{Reserved: false}, nil
}

// GetPublicEndpoint returns the hostname clients use to reach this proxpass.
func (h *SessionHandler) GetPublicEndpoint(
	ctx context.Context, _ GetPublicEndpointRequestObject,
) (GetPublicEndpointResponseObject, error) {
	if _, err := h.callerIdentity(ctx); err != nil {
		return endpointAuthFailure(err)
	}

	endpoint, err := h.repo.GetSetting(ctx, db.SettingPublicEndpoint)
	if err != nil {
		return nil, err
	}
	return GetPublicEndpoint200JSONResponse{Endpoint: endpoint}, nil
}

// --- shared helpers ---

// authFailureReason turns a callerIdentity error into the terse reason the
// 401 body carries, or "" when the error was not an authentication problem
// and belongs in a 500 instead.
//
// The two reasons are kept distinct for the operator reading a log, not for
// the caller: both mean "present a valid credential".
func authFailureReason(err error) string {
	switch {
	case errors.Is(err, errNoCredential):
		return reasonMissingToken
	case errors.Is(err, db.ErrNoSuchToken):
		return reasonInvalidToken
	default:
		return ""
	}
}

func listGuestsAuthFailure(err error) (ListSessionGuestsResponseObject, error) {
	reason := authFailureReason(err)
	if reason == "" {
		return nil, err
	}
	return ListSessionGuests401JSONResponse{
		UnauthorizedJSONResponse: UnauthorizedJSONResponse{Error: reason},
	}, nil
}

func reservedAuthFailure(err error) (IsLoginNameReservedResponseObject, error) {
	reason := authFailureReason(err)
	if reason == "" {
		return nil, err
	}
	return IsLoginNameReserved401JSONResponse{
		UnauthorizedJSONResponse: UnauthorizedJSONResponse{Error: reason},
	}, nil
}

func endpointAuthFailure(err error) (GetPublicEndpointResponseObject, error) {
	reason := authFailureReason(err)
	if reason == "" {
		return nil, err
	}
	return GetPublicEndpoint401JSONResponse{
		UnauthorizedJSONResponse: UnauthorizedJSONResponse{Error: reason},
	}, nil
}

// mayReach reports whether identity is allowed to reach guestID.
//
// The administrator reaches everything; everyone else is checked against the
// access rules. This is the single place that decides, so the list and
// connect endpoints cannot drift apart.
func (h *SessionHandler) mayReach(
	ctx context.Context, identity *models.SessionIdentity, guestID int64,
) (bool, error) {
	if identity.IsAdmin {
		return true, nil
	}
	return h.repo.HasAccess(ctx, identity.ClientID, guestID)
}

// accessibleGuests returns the guests identity may reach.
func (h *SessionHandler) accessibleGuests(
	ctx context.Context, identity *models.SessionIdentity,
) ([]*models.Guest, error) {
	guests, err := h.repo.ListGuests(ctx)
	if err != nil {
		return nil, err
	}
	if identity.IsAdmin {
		return guests, nil
	}
	out := make([]*models.Guest, 0, len(guests))
	for _, g := range guests {
		ok, err := h.repo.HasAccess(ctx, identity.ClientID, g.ID)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, g)
		}
	}
	return out, nil
}

// instanceNames maps instance id to name.
//
// Only the names: this is for labeling a guest list, and the instances
// themselves carry secrets that have no business in that response.
func (h *SessionHandler) instanceNames(ctx context.Context) (map[int64]string, error) {
	instances, err := h.repo.ListProxmoxInstances(ctx)
	if err != nil {
		return nil, err
	}
	names := make(map[int64]string, len(instances))
	for _, inst := range instances {
		names[inst.ID] = inst.Name
	}
	return names, nil
}

// findGuest returns the guest with this id, or nil when there is none.
//
// A missing guest is not an error: the caller turns it into the same refusal
// as a forbidden one, deliberately.
func (h *SessionHandler) findGuest(ctx context.Context, id int64) (*models.Guest, error) {
	guest, err := h.repo.GetGuestByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // "no such guest" is the caller's to report
	}
	if err != nil {
		return nil, err
	}
	return guest, nil
}

func (h *SessionHandler) findInstance(ctx context.Context, id int64) (*models.ProxmoxInstance, error) {
	instances, err := h.repo.ListProxmoxInstances(ctx)
	if err != nil {
		return nil, err
	}
	for _, inst := range instances {
		if inst.ID == id {
			return inst, nil
		}
	}
	return nil, nil //nolint:nilnil // "no such instance" is reported by the caller
}

// instanceCredentials converts an instance into the wire shape.
//
// A key configured as a PATH is read here and returned inline. The session
// cannot read that file -- that is the whole point of moving it off the
// database -- so handing it a path would leave it unable to connect.
func (h *SessionHandler) instanceCredentials(inst *models.ProxmoxInstance) (InstanceCredentials, error) {
	out := InstanceCredentials{
		ID:             inst.ID,
		Name:           inst.Name,
		APIURL:         inst.APIURL,
		ConnectionType: InstanceCredentialsConnectionType(inst.ConnectionType),
		Node:           inst.Node,
	}
	setIfNotEmpty(&out.APITokenID, inst.APITokenID)
	setIfNotEmpty(&out.APITokenSecret, inst.APITokenSecret)
	setIfNotEmpty(&out.SSHHost, inst.SSHHost)
	setIfNotEmpty(&out.SSHUser, inst.SSHUser)
	if inst.SSHPort != 0 {
		port := inst.SSHPort
		out.SSHPort = &port
	}

	// The deployment's key, which is the only one there is.
	//
	// Resolved HERE rather than passed along as a path, because the session
	// cannot read the file: it is root-owned, and the session is not root.
	// That is the point -- the key reaches a session only through this
	// response, and only once the access check above has passed.
	//
	// Read per connection rather than cached at startup, so replacing the
	// file takes effect on the next connection instead of at the next
	// restart. It is a small local read on a path that already does several.
	key, err := models.ReadSSHKey()
	if err != nil {
		return InstanceCredentials{}, err
	}
	setIfNotEmpty(&out.SSHKey, key)
	return out, nil
}

func setIfNotEmpty(dst **string, value string) {
	if value == "" {
		return
	}
	v := value
	*dst = &v
}

func guestResponse(g *models.Guest, instanceName string) Guest {
	return Guest{
		ID:           g.ID,
		Name:         g.Name,
		Type:         GuestType(g.Type),
		Status:       GuestStatus(g.Status),
		ProxmoxID:    g.ProxmoxID,
		InstanceID:   g.InstanceID,
		InstanceName: instanceName,
	}
}

func forbidden() ConnectSessionGuest403JSONResponse {
	return ConnectSessionGuest403JSONResponse{Error: "no such guest"}
}
