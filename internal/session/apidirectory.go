package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"proxpass/internal/api"
	"proxpass/internal/models"
)

// ErrAccessDenied reports a guest this session may not reach.
//
// It is also what a guest that does not exist produces, deliberately:
// telling the two apart would let a caller map the cluster by trying ids.
var ErrAccessDenied = errors.New("access denied")

// guestFromAPI converts a wire guest into the model the console and CLI
// already take.
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

// instanceFromAPI converts wire credentials into the model.
//
// The pointer fields are absent rather than empty when an instance does not
// use them -- an SSH instance has no API token -- so each is dereferenced
// only when present.
func instanceFromAPI(c *api.InstanceCredentials) *models.ProxmoxInstance {
	inst := &models.ProxmoxInstance{
		ID:               c.ID,
		Name:             c.Name,
		APIURL:           c.APIURL,
		ConsoleTransport: models.ConsoleTransport(c.ConsoleTransport),
		Node:             c.Node,
	}
	if c.APITokenID != nil {
		inst.APITokenID = *c.APITokenID
	}
	if c.APITokenSecret != nil {
		inst.APITokenSecret = *c.APITokenSecret
	}
	if c.InsecureTLS != nil {
		inst.InsecureTLS = *c.InsecureTLS
	}
	if c.InsecureSSH != nil {
		inst.InsecureSSH = *c.InsecureSSH
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
	if c.SSHFingerprints != nil {
		inst.SSHFingerprints = *c.SSHFingerprints
	}
	return inst
}

// instanceSSHKey returns the key the server sent for an instance.
//
// Separate from instanceFromAPI because the key is not part of the instance:
// it belongs to the deployment, and the server read it for this one
// connection.
func instanceSSHKey(c *api.InstanceCredentials) string {
	if c.SSHKey == nil {
		return ""
	}
	return *c.SSHKey
}

// APIDirectory serves a session from the loopback API.
//
// This is what a client session uses, and the reason the whole exchange
// exists: it holds no database handle, so the Proxmox API token secrets and
// instance SSH private keys in the database are out of its reach. It gets
// credentials for exactly the guest it is connecting to, at the moment it
// connects, and only after the server has checked it may.
type APIDirectory struct {
	Client *APIClient
}

// AccessibleGuests returns the guests this session may reach.
//
// The filtering happens server-side: what comes back is already scoped to
// this session's identity, so there is nothing to filter here.
func (d *APIDirectory) AccessibleGuests(ctx context.Context) ([]*GuestInfo, error) {
	var guests []api.Guest
	if err := d.Client.get(ctx, "/session/guests", &guests); err != nil {
		return nil, fmt.Errorf("listing guests: %w", err)
	}

	out := make([]*GuestInfo, 0, len(guests))
	for _, g := range guests {
		out = append(out, &GuestInfo{
			Guest:        guestFromAPI(&g),
			InstanceName: g.InstanceName,
		})
	}
	return out, nil
}

// Connect asks for the credentials to reach one guest.
func (d *APIDirectory) Connect(ctx context.Context, guestID int64) (*ConnectInfo, error) {
	var info api.ConnectInfo
	err := d.Client.post(ctx,
		"/session/connect/"+strconv.FormatInt(guestID, 10), &info)
	if errors.Is(err, errForbidden) {
		return nil, ErrAccessDenied
	}
	if err != nil {
		return nil, fmt.Errorf("connecting to guest %d: %w", guestID, err)
	}
	return &ConnectInfo{
		Guest:    guestFromAPI(&info.Guest),
		Instance: instanceFromAPI(&info.Instance),
		SSHKey:   instanceSSHKey(&info.Instance),
	}, nil
}

// AccessibleInstances returns the nodes this session may reach.
//
// Filtered server-side, like AccessibleGuests, so there is nothing to
// filter here.
func (d *APIDirectory) AccessibleInstances(ctx context.Context) ([]*models.ProxmoxInstance, error) {
	var instances []api.Instance
	if err := d.Client.get(ctx, "/session/instances", &instances); err != nil {
		return nil, fmt.Errorf("listing instances: %w", err)
	}

	out := make([]*models.ProxmoxInstance, 0, len(instances))
	for _, inst := range instances {
		// Only the three fields the response carries. This is the
		// credential-free shape, so the rest of ProxmoxInstance stays
		// zero rather than being invented here.
		out = append(out, &models.ProxmoxInstance{
			ID:   inst.ID,
			Name: inst.Name,
			Node: inst.Node,
		})
	}
	return out, nil
}

// ConnectNode asks for the credentials to reach one node.
func (d *APIDirectory) ConnectNode(ctx context.Context, instanceID int64) (*NodeInfo, error) {
	var creds api.InstanceCredentials
	err := d.Client.post(ctx,
		"/session/node/"+strconv.FormatInt(instanceID, 10), &creds)
	if errors.Is(err, errForbidden) {
		return nil, ErrAccessDenied
	}
	if err != nil {
		return nil, fmt.Errorf("connecting to node %d: %w", instanceID, err)
	}
	return &NodeInfo{
		Instance: instanceFromAPI(&creds),
		SSHKey:   instanceSSHKey(&creds),
	}, nil
}

// PublicEndpoint returns the configured endpoint, or "" when unset.
func (d *APIDirectory) PublicEndpoint(ctx context.Context) (string, error) {
	var out struct {
		Endpoint string `json:"endpoint"`
	}
	if err := d.Client.get(ctx, "/session/public-endpoint", &out); err != nil {
		return "", fmt.Errorf("reading the public endpoint: %w", err)
	}
	return out.Endpoint, nil
}

// get and post issue an authenticated request with the session credential.
func (c *APIClient) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, c.credential, out)
}

func (c *APIClient) post(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodPost, path, c.credential, out)
}

// ReportActivity tells the server what this session is doing, for the activity
// log. The server resolves who from the credential and records the row; the
// session never touches the database. command is sent only for the "command"
// kind. Best-effort: callers ignore the error so a reporting hiccup never
// affects the session. The endpoint returns 204 with no body, so out is nil.
func (d *APIDirectory) ReportActivity(ctx context.Context, kind, command string) error {
	body := api.SessionActivityReport{Kind: api.SessionActivityReportKind(kind)}
	if command != "" {
		body.Command = &command
	}
	return d.Client.postJSON(ctx, "/session/activity", body, nil)
}
