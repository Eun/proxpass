package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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

// ListSessionInstances returns the Proxmox nodes the caller may reach.
//
// The node counterpart of ListSessionGuests, filtered the same way and for
// the same reason: a caller that may not reach a node does not see it.
//
// Not derived from the guest list. A grant on an instance and a grant on a
// guest it hosts are independent -- granting the node says nothing about
// the guests and vice versa -- so the two answers generally differ, and
// deriving one from the other would silently turn either grant into both.
func (h *SessionHandler) ListSessionInstances(
	ctx context.Context, _ ListSessionInstancesRequestObject,
) (ListSessionInstancesResponseObject, error) {
	identity, err := h.callerIdentity(ctx)
	if err != nil {
		return listInstancesAuthFailure(err)
	}

	instances, err := h.accessibleInstances(ctx, identity)
	if err != nil {
		return nil, err
	}

	out := make([]Instance, 0, len(instances))
	for _, inst := range instances {
		out = append(out, instanceResponse(inst))
	}
	return ListSessionInstances200JSONResponse(out), nil
}

// ConnectSessionNode hands over the credentials for reaching one node.
//
// As with ConnectSessionGuest, the access check happens HERE, from the
// stored identity: being able to name an instance is not permission to
// reach it, and this endpoint may not assume the list endpoint filtered.
func (h *SessionHandler) ConnectSessionNode(
	ctx context.Context, request ConnectSessionNodeRequestObject,
) (ConnectSessionNodeResponseObject, error) {
	identity, err := h.callerIdentity(ctx)
	if err != nil {
		reason := authFailureReason(err)
		if reason == "" {
			return nil, err
		}
		return ConnectSessionNode401JSONResponse{
			UnauthorizedJSONResponse: UnauthorizedJSONResponse{Error: reason},
		}, nil
	}

	inst, err := h.findInstance(ctx, request.InstanceID)
	if err != nil {
		return nil, err
	}
	// An instance that does not exist and one the caller may not reach get
	// the same answer, for the same reason as the guest endpoint: otherwise
	// trying ids would reveal what the cluster contains.
	if inst == nil {
		return forbiddenNode(), nil
	}
	allowed, err := h.mayReachInstance(ctx, identity, inst.ID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return forbiddenNode(), nil
	}

	// A node is reached over SSH whatever the console transport, so an
	// instance with no ssh_host cannot be opened at all. That is a
	// configuration problem rather than a permission one, so it is reported
	// as such instead of being folded into the refusal above -- the caller
	// was granted this node and is entitled to know why it will not open.
	if inst.SSHHost == "" {
		return nil, fmt.Errorf(
			"instance %q has no ssh-host, so its node cannot be reached: "+
				"set one with `instance update --name %s --ssh-host <host>'",
			inst.Name, inst.Name)
	}

	credentials, err := h.instanceCredentials(inst)
	if err != nil {
		return nil, err
	}
	return ConnectSessionNode200JSONResponse(credentials), nil
}

// IsLoginNameReserved reports whether a login name means "browse".
//
// Only the administrator's name is, and the session decides that for itself
// without asking (session.isReservedLoginName). The endpoint remains so an
// older session binary keeps working against a newer server; it no longer
// consults the client list, so a client name is now reported as ordinary
// and resolves to the guest it names.
func (h *SessionHandler) IsLoginNameReserved(
	ctx context.Context, request IsLoginNameReservedRequestObject,
) (IsLoginNameReservedResponseObject, error) {
	if _, err := h.callerIdentity(ctx); err != nil {
		return reservedAuthFailure(err)
	}
	return IsLoginNameReserved200JSONResponse{
		Reserved: models.NamesEqual(request.Params.Name, AdminUser),
	}, nil
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

func listInstancesAuthFailure(err error) (ListSessionInstancesResponseObject, error) {
	reason := authFailureReason(err)
	if reason == "" {
		return nil, err
	}
	return ListSessionInstances401JSONResponse{
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

// mayReachInstance reports whether identity is allowed to reach the node
// instanceID.
//
// The node counterpart of mayReach, and the single place that decides, so
// the list and connect endpoints cannot drift apart.
//
// HasInstanceAccess deliberately does not consult the default policy; see
// the comment on it. The administrator short-circuit is the same, because
// an administrator already reaches every node by other means.
func (h *SessionHandler) mayReachInstance(
	ctx context.Context, identity *models.SessionIdentity, instanceID int64,
) (bool, error) {
	if identity.IsAdmin {
		return true, nil
	}
	return h.repo.HasInstanceAccess(ctx, identity.ClientID, instanceID)
}

// accessible filters a list to the rows identity may reach.
//
// Shared by the guest and node lists, which differ only in what they list
// and which rule they ask about. Written once so the two cannot drift: the
// administrator short-circuit and the fail-closed loop are the part that
// must not vary, and a second copy is a second place to get them wrong.
//
// Note the filter is applied per row rather than pushed into SQL. That is
// deliberate -- HasAccess and HasInstanceAccess are where the tiers are
// decided, and duplicating their logic in a query is how the two would
// come to disagree.
func accessible[T any](
	ctx context.Context,
	identity *models.SessionIdentity,
	list func(context.Context) ([]T, error),
	id func(T) int64,
	mayReach func(context.Context, int64, int64) (bool, error),
) ([]T, error) {
	rows, err := list(ctx)
	if err != nil {
		return nil, err
	}
	if identity.IsAdmin {
		return rows, nil
	}
	out := make([]T, 0, len(rows))
	for _, row := range rows {
		ok, err := mayReach(ctx, identity.ClientID, id(row))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, row)
		}
	}
	return out, nil
}

// accessibleInstances returns the instances identity may reach.
//
// Instances with no ssh-host are left out. A node is reached only over SSH,
// so one without a host cannot be opened at all, and listing it would offer
// a choice that always fails -- the picker would show it, the user would
// select it, and the connect endpoint would report a configuration fault.
// Being unable to reach it is not a permission problem, which is why
// ConnectSessionNode still reports it rather than refusing: a caller naming
// such an instance directly is entitled to know why it will not open.
func (h *SessionHandler) accessibleInstances(
	ctx context.Context, identity *models.SessionIdentity,
) ([]*models.ProxmoxInstance, error) {
	granted, err := accessible(ctx, identity,
		h.repo.ListProxmoxInstances,
		func(inst *models.ProxmoxInstance) int64 { return inst.ID },
		h.repo.HasInstanceAccess)
	if err != nil {
		return nil, err
	}
	out := make([]*models.ProxmoxInstance, 0, len(granted))
	for _, inst := range granted {
		if inst.SSHHost == "" {
			continue
		}
		out = append(out, inst)
	}
	return out, nil
}

// accessibleGuests returns the guests identity may reach.
func (h *SessionHandler) accessibleGuests(
	ctx context.Context, identity *models.SessionIdentity,
) ([]*models.Guest, error) {
	return accessible(ctx, identity,
		h.repo.ListGuests,
		func(g *models.Guest) int64 { return g.ID },
		h.repo.HasAccess)
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
		ID:               inst.ID,
		Name:             inst.Name,
		APIURL:           inst.APIURL,
		ConsoleTransport: InstanceCredentialsConsoleTransport(inst.ConsoleTransport),
		Node:             inst.Node,
	}
	setIfNotEmpty(&out.APITokenID, inst.APITokenID)
	setIfNotEmpty(&out.APITokenSecret, inst.APITokenSecret)
	setIfNotEmpty(&out.SSHHost, inst.SSHHost)
	setIfNotEmpty(&out.SSHUser, inst.SSHUser)
	setIfNotEmpty(&out.SSHFingerprint, inst.SSHFingerprint)
	if inst.SSHPort != 0 {
		port := inst.SSHPort
		out.SSHPort = &port
	}
	// Carry both insecure flags so the session verifies (or skips verifying)
	// TLS and SSH exactly as the stored instance does. Always set them, even
	// when false, so a verified instance is never silently treated as insecure.
	insecureTLS := inst.InsecureTLS
	out.InsecureTLS = &insecureTLS
	insecureSSH := inst.InsecureSSH
	out.InsecureSSH = &insecureSSH

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

// instanceResponse converts an instance into the wire shape for a LIST.
//
// Deliberately not instanceCredentials: this is the shape that carries no
// secrets, for a list a session holds for its whole life. The two exist
// separately so that adding a field to the credential shape cannot leak it
// into the list by accident.
func instanceResponse(inst *models.ProxmoxInstance) Instance {
	return Instance{
		ID:   inst.ID,
		Name: inst.Name,
		Node: inst.Node,
	}
}

func forbidden() ConnectSessionGuest403JSONResponse {
	return ConnectSessionGuest403JSONResponse{Error: "no such guest"}
}

// forbiddenNode is the node counterpart of forbidden, and is likewise the
// answer both for a node the caller may not reach and for one that does not
// exist.
func forbiddenNode() ConnectSessionNode403JSONResponse {
	return ConnectSessionNode403JSONResponse{Error: "no such instance"}
}
