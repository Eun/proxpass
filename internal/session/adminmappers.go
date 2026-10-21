package session

import (
	"proxpass/internal/api"
	"proxpass/internal/models"
)

// This file converts between the internal storage models (internal/models)
// and the generated wire schemas (internal/api), for the admin repository's
// /v1 calls. It is the inverse of internal/api/adminmappers.go, which does the
// same job on the server side; those mappers are unexported in package api, so
// the session side carries its own.
//
// The two sets of types share json tags but are distinct Go types on purpose:
// the wire shape is owned by the OpenAPI spec and the storage shape by the
// database. Every field is copied explicitly so that adding a field to either
// side is a compile error until it is handled here, rather than a value that
// silently stops crossing the boundary.

// --- instances ---

func toAPIInstance(inst *models.ProxmoxInstance) api.ProxmoxInstance {
	return api.ProxmoxInstance{
		ID:               inst.ID,
		Name:             inst.Name,
		APIURL:           inst.APIURL,
		APITokenID:       inst.APITokenID,
		APITokenSecret:   inst.APITokenSecret,
		ConsoleTransport: api.ProxmoxInstanceConsoleTransport(inst.ConsoleTransport),
		Node:             inst.Node,
		InsecureTLS:      inst.InsecureTLS,
		InsecureSSH:      inst.InsecureSSH,
		SSHHost:          inst.SSHHost,
		SSHPort:          inst.SSHPort,
		SSHUser:          inst.SSHUser,
		SSHFingerprint:   inst.SSHFingerprint,
	}
}

func fromAPIInstance(in *api.ProxmoxInstance) *models.ProxmoxInstance {
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
		SSHFingerprint:   in.SSHFingerprint,
	}
}

// --- clients ---

// The schema type is api.AdminClient rather than api.Client: the generated
// Client is the HTTP client struct (oapi-codegen's client: true), and the
// admin client schema was renamed to avoid the collision.
func toAPIClient(c *models.Client) api.AdminClient {
	return api.AdminClient{
		ID:         c.ID,
		Name:       c.Name,
		PublicKeys: c.PublicKeys,
		GroupIds:   c.GroupIDs,
	}
}

func fromAPIClient(in *api.AdminClient) *models.Client {
	return &models.Client{
		ID:         in.ID,
		Name:       in.Name,
		PublicKeys: in.PublicKeys,
		GroupIDs:   in.GroupIds,
	}
}

// --- groups ---

func toAPIGroup(g *models.Group) api.ClientGroup {
	return api.ClientGroup{
		ID:        g.ID,
		Name:      g.Name,
		ClientIds: g.ClientIDs,
	}
}

func fromAPIGroup(in *api.ClientGroup) *models.Group {
	return &models.Group{
		ID:        in.ID,
		Name:      in.Name,
		ClientIDs: in.ClientIds,
	}
}

// --- guests ---

func fromAPIGuestRow(in *api.GuestRow) *models.Guest {
	return &models.Guest{
		ID:         in.ID,
		InstanceID: in.InstanceID,
		Name:       in.Name,
		ProxmoxID:  in.ProxmoxID,
		Status:     models.Status(in.Status),
		Type:       models.GuestType(in.Type),
	}
}

// --- access rules ---

func fromAPIAccessRuleRow(in *api.AccessRuleRow) *models.AccessRuleRow {
	return &models.AccessRuleRow{
		ID:        in.ID,
		Type:      models.RuleType(in.Type),
		SubjectID: in.SubjectID,
		GuestID:   in.GuestID,
	}
}

func fromAPIInstanceAccessRuleRow(in *api.InstanceAccessRuleRow) *models.InstanceAccessRuleRow {
	return &models.InstanceAccessRuleRow{
		ID:         in.ID,
		Type:       models.RuleType(in.Type),
		SubjectID:  in.SubjectID,
		InstanceID: in.InstanceID,
	}
}

// --- default policy ---

func toAPIDefaultPolicy(p *models.DefaultAccessPolicy) api.DefaultAccessPolicy {
	return api.DefaultAccessPolicy{
		AuthorizedClientIds: p.AuthorizedClientIDs,
		AuthorizedGroupIds:  p.AuthorizedGroupIDs,
	}
}

func fromAPIDefaultPolicy(in *api.DefaultAccessPolicy) *models.DefaultAccessPolicy {
	return &models.DefaultAccessPolicy{
		AuthorizedClientIDs: in.AuthorizedClientIds,
		AuthorizedGroupIDs:  in.AuthorizedGroupIds,
	}
}
