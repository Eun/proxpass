package session

import (
	"context"

	"proxpass/internal/models"
)

// Directory is everything a session needs to know about the cluster.
//
// It exists so that a session can be served either by the database
// directly or by the loopback API, without the code between caring which.
// The API-backed one is what a client session uses: it must not hold
// database access, because the database holds Proxmox API token secrets and
// instance SSH private keys, and a session that can read those can take over
// the cluster.
//
// Every method is already scoped to the caller. AccessibleGuests returns
// what this session may reach rather than everything, and Connect refuses a
// guest it may not. Scoping is the implementation's job precisely so that
// no caller can forget to do it.
type Directory interface {
	// AccessibleGuests returns the guests this session may reach, each
	// carrying the name of the instance hosting it. No credentials.
	AccessibleGuests(ctx context.Context) ([]*GuestInfo, error)

	// Connect returns what is needed to open one guest's console, after
	// checking that this session may reach it. ErrAccessDenied when it
	// may not -- which is also the answer for a guest that does not
	// exist, so that ids cannot be used to enumerate the cluster.
	Connect(ctx context.Context, guestID int64) (*ConnectInfo, error)

	// AccessibleInstances returns the Proxmox nodes this session may reach
	// in their own right. No credentials.
	//
	// Independent of AccessibleGuests: a grant on a node says nothing
	// about its guests and a grant on a guest says nothing about its
	// node, so the two lists generally differ and neither is derived
	// from the other. In particular this is NOT the same as the
	// instances named by the visible guests -- see namedInstances.
	AccessibleInstances(ctx context.Context) ([]*models.ProxmoxInstance, error)

	// ConnectNode returns what is needed to open a shell on one node,
	// after checking that this session may reach it. ErrAccessDenied
	// when it may not -- which is also the answer for an instance that
	// does not exist, so that ids cannot enumerate the cluster.
	ConnectNode(ctx context.Context, instanceID int64) (*NodeInfo, error)

	// PublicEndpoint is the hostname clients use to reach this proxpass,
	// shown in the status bar. Empty when unset, which is not an error.
	PublicEndpoint(ctx context.Context) (string, error)
}

// NodeInfo is one Proxmox node plus what it takes to reach it.
//
// The node counterpart of ConnectInfo, and carries the key for the same
// reason and on the same terms: it belongs to the deployment rather than to
// the instance, a session cannot read the file, and it arrives only once
// the access check has passed.
type NodeInfo struct {
	Instance *models.ProxmoxInstance

	// SSHKey is the PEM private key to reach the node with. Never empty
	// in practice -- a node is reachable only over SSH, so a response
	// without a key cannot be connected with -- but it is not this
	// type's job to enforce that.
	SSHKey string
}

// GuestInfo is a guest as the picker and the client CLI need it.
//
// Deliberately carries no credentials: a session holds this list for its
// whole life and connects to at most one of them.
type GuestInfo struct {
	Guest *models.Guest

	// InstanceName labels the guest and is matched against the "@instance"
	// suffix of a login name. It is the only thing about an instance that
	// browsing needs.
	InstanceName string
}

// guestModels extracts the guests from a scoped list.
func guestModels(guests []*GuestInfo) []*models.Guest {
	out := make([]*models.Guest, 0, len(guests))
	for _, g := range guests {
		out = append(out, g.Guest)
	}
	return out
}

// namedInstances returns a stand-in instance per distinct instance name in
// the list.
//
// The client CLI and the login-name parser match on instance ID and name
// and read nothing else -- checked at every call site -- so a record
// carrying just those two is all they need, and is all a session may have:
// the real ones hold credentials. The set is derived from the guests the
// caller can already see, so it cannot disclose an instance it has no guest
// on.
func namedInstances(guests []*GuestInfo) []*models.ProxmoxInstance {
	seen := make(map[int64]struct{}, len(guests))
	out := make([]*models.ProxmoxInstance, 0, len(guests))
	for _, g := range guests {
		if _, ok := seen[g.Guest.InstanceID]; ok {
			continue
		}
		seen[g.Guest.InstanceID] = struct{}{}
		out = append(out, &models.ProxmoxInstance{
			ID:   g.Guest.InstanceID,
			Name: g.InstanceName,
		})
	}
	return out
}

// ConnectInfo is one guest plus the credentials for its instance.
type ConnectInfo struct {
	Guest    *models.Guest
	Instance *models.ProxmoxInstance

	// SSHKey is the PEM private key to reach Instance's Proxmox host with,
	// empty for a termproxy instance which needs none.
	//
	// It travels beside the instance rather than on it because it is not a
	// property of the instance: there is ONE key for the whole deployment,
	// and the API reads it per connection and sends it here. A session
	// cannot read the file itself -- it is root-owned, and a session is not
	// root -- so this response is the only way it arrives.
	SSHKey string
}
