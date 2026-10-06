package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"proxpass/internal/api"
)

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
	}, nil
}

// IsLoginNameReserved asks about one name.
func (d *APIDirectory) IsLoginNameReserved(ctx context.Context, name string) (bool, error) {
	var out struct {
		Reserved bool `json:"reserved"`
	}
	path := "/session/login-name-reserved?name=" + url.QueryEscape(name)
	if err := d.Client.get(ctx, path, &out); err != nil {
		return false, fmt.Errorf("checking login name: %w", err)
	}
	return out.Reserved, nil
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
