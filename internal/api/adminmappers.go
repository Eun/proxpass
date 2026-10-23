package api

import (
	"strings"

	"proxpass/internal/models"
)

// This file converts between the internal models (internal/models) and the
// generated wire schemas, and classifies the domain errors the repository
// returns into the HTTP shapes the admin handlers answer with.
//
// The two sets of types share json tags but are distinct Go types on
// purpose: the wire shape is owned by the OpenAPI spec and the storage shape
// by the database, and letting one be the other would couple a schema change
// to a migration. Every field is mapped explicitly here so that adding a
// field to either side is a compile error until it is handled, rather than a
// value that silently stops crossing the boundary.

// --- error classification ---
//
// The repository reports domain conflicts as formatted errors rather than
// sentinels: an instance name clash is an "... already exists" message, and
// a client/group/admin-key clash surfaces as the driver's raw UNIQUE
// violation. Both mean the same thing to a caller -- the row is already
// there -- so both are matched here and turned into a 409. Matching on the
// message is unavoidable because that is all the layer below hands up; it is
// kept in one place so the handlers do not each reimplement it.

// isConflict reports whether err is a uniqueness clash that should become a
// 409 rather than a 500.
func isConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "UNIQUE constraint failed")
}

// --- instances ---

func toAPIInstance(inst *models.ProxmoxInstance) ProxmoxInstance {
	return ProxmoxInstance{
		ID:               inst.ID,
		Name:             inst.Name,
		APIURL:           inst.APIURL,
		APITokenID:       inst.APITokenID,
		APITokenSecret:   inst.APITokenSecret,
		ConsoleTransport: ProxmoxInstanceConsoleTransport(inst.ConsoleTransport),
		Node:             inst.Node,
		InsecureTLS:      inst.InsecureTLS,
		InsecureSSH:      inst.InsecureSSH,
		SSHHost:          inst.SSHHost,
		SSHPort:          inst.SSHPort,
		SSHUser:          inst.SSHUser,
		SSHFingerprints:  inst.SSHFingerprints,
	}
}

func fromAPIInstance(in *ProxmoxInstance) *models.ProxmoxInstance {
	return &models.ProxmoxInstance{
		ID:               in.ID,
		Name:             in.Name,
		APIURL:           in.APIURL,
		APITokenID:       in.APITokenID,
		APITokenSecret:   in.APITokenSecret,
		ConsoleTransport: models.ConsoleTransport(in.ConsoleTransport),
		Node:             in.Node,
		InsecureTLS:      in.InsecureTLS,
		InsecureSSH:      in.InsecureSSH,
		SSHHost:          in.SSHHost,
		SSHPort:          in.SSHPort,
		SSHUser:          in.SSHUser,
		SSHFingerprints:  in.SSHFingerprints,
	}
}

// --- clients ---

// The schema type is AdminClient rather than Client: the generated Client is
// now the HTTP client struct (oapi-codegen's client: true), and the admin
// client schema was renamed to avoid the collision. See api/openapi.yaml.
func toAPIClient(c *models.Client) AdminClient {
	return AdminClient{
		ID:         c.ID,
		Name:       c.Name,
		PublicKeys: nonNilStrings(c.PublicKeys),
		GroupIds:   nonNilInts(c.GroupIDs),
	}
}

func fromAPIClient(in *AdminClient) *models.Client {
	return &models.Client{
		ID:         in.ID,
		Name:       in.Name,
		PublicKeys: in.PublicKeys,
		GroupIDs:   in.GroupIds,
	}
}

// --- groups ---

func toAPIGroup(g *models.Group) ClientGroup {
	return ClientGroup{
		ID:        g.ID,
		Name:      g.Name,
		ClientIds: nonNilInts(g.ClientIDs),
	}
}

func fromAPIGroup(in *ClientGroup) *models.Group {
	return &models.Group{
		ID:        in.ID,
		Name:      in.Name,
		ClientIDs: in.ClientIds,
	}
}

// --- guests ---

func toAPIGuestRow(g *models.Guest) GuestRow {
	return GuestRow{
		ID:         g.ID,
		InstanceID: g.InstanceID,
		Name:       g.Name,
		ProxmoxID:  g.ProxmoxID,
		Status:     GuestRowStatus(g.Status),
		Type:       GuestRowType(g.Type),
	}
}

// --- access rules ---

func toAPIAccessRuleRow(r *models.AccessRuleRow) AccessRuleRow {
	return AccessRuleRow{
		ID:        r.ID,
		Type:      RuleType(r.Type),
		SubjectID: r.SubjectID,
		GuestID:   r.GuestID,
	}
}

func toAPIInstanceAccessRuleRow(r *models.InstanceAccessRuleRow) InstanceAccessRuleRow {
	return InstanceAccessRuleRow{
		ID:         r.ID,
		Type:       RuleType(r.Type),
		SubjectID:  r.SubjectID,
		InstanceID: r.InstanceID,
	}
}

// --- default policy ---

func toAPIDefaultPolicy(p *models.DefaultAccessPolicy) DefaultAccessPolicy {
	return DefaultAccessPolicy{
		AuthorizedClientIds: nonNilInts(p.AuthorizedClientIDs),
		AuthorizedGroupIds:  nonNilInts(p.AuthorizedGroupIDs),
	}
}

func fromAPIDefaultPolicy(in *DefaultAccessPolicy) *models.DefaultAccessPolicy {
	return &models.DefaultAccessPolicy{
		AuthorizedClientIDs: in.AuthorizedClientIds,
		AuthorizedGroupIDs:  in.AuthorizedGroupIds,
	}
}

// nonNilStrings returns s, or an empty non-nil slice when s is nil, so a
// required array field serializes as [] rather than null. The spec marks
// public_keys/group_ids/client_ids as required arrays, and a stored row with
// none reads them back as a nil slice.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilInts(s []int64) []int64 {
	if s == nil {
		return []int64{}
	}
	return s
}
