package api

import (
	"context"
	"testing"

	"proxpass/internal/models"
	"proxpass/internal/proxmox"
)

// fakeDiscoverer returns a fixed guest list, so a test can assert what gets
// stored without a real Proxmox API.
type fakeDiscoverer struct{ guests []*models.Guest }

func (f fakeDiscoverer) DiscoverGuests(context.Context) ([]*models.Guest, error) {
	return f.guests, nil
}

// addInstanceBody returns a minimal valid AddInstance body, reusing the shared
// instance test constants so no string literals repeat across tests.
func addInstanceBody() AddInstanceJSONRequestBody {
	return AddInstanceJSONRequestBody{
		Name:             testInstanceName,
		APIURL:           "https://pve.example:8006",
		APITokenID:       "root@pam!tok",
		APITokenSecret:   "tok-secret",
		ConsoleTransport: ProxmoxInstanceConsoleTransportTermproxy,
		Node:             testInstanceName,
	}
}

// Adding an instance triggers an immediate discovery, so its running guests
// appear right away instead of only after the next scheduled poll.
func TestAddInstanceDiscoversGuestsImmediately(t *testing.T) {
	h, _, ctx := newAdminHandler(t)

	// The discoverer reports one running guest for whatever instance it is
	// handed; StoreGuests will persist it against the new instance's id.
	h.WithDiscoverer(func(inst *models.ProxmoxInstance) proxmox.GuestDiscoverer {
		return fakeDiscoverer{guests: []*models.Guest{
			{Type: models.GuestTypeCT, Name: testGuestName, Status: models.StatusRunning, ProxmoxID: 100, InstanceID: inst.ID},
		}}
	})

	body := addInstanceBody()
	if _, err := h.AddInstance(ctx, AddInstanceRequestObject{Body: &body}); err != nil {
		t.Fatalf("AddInstance: %v", err)
	}

	// The guest the discoverer reported is now listed, with no manual
	// discovery call in between.
	resp, err := h.ListGuests(ctx, ListGuestsRequestObject{})
	if err != nil {
		t.Fatalf("ListGuests: %v", err)
	}
	guests, ok := resp.(ListGuests200JSONResponse)
	if !ok {
		t.Fatalf("ListGuests returned %T, want 200", resp)
	}
	if len(guests) != 1 || guests[0].Name != testGuestName {
		t.Fatalf("ListGuests after add = %+v, want the discovered ct100", guests)
	}
}

// A discovery failure on add does not fail the add: the node is stored and the
// next pass retries. (The fake returns an error here.)
func TestAddInstanceSucceedsEvenIfDiscoveryFails(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	h.WithDiscoverer(func(*models.ProxmoxInstance) proxmox.GuestDiscoverer {
		return errDiscoverer{}
	})

	body := addInstanceBody()
	resp, err := h.AddInstance(ctx, AddInstanceRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("AddInstance returned a hard error on discovery failure: %v", err)
	}
	if _, ok := resp.(AddInstance201JSONResponse); !ok {
		t.Fatalf("AddInstance returned %T, want 201 despite discovery failing", resp)
	}
}

type errDiscoverer struct{}

func (errDiscoverer) DiscoverGuests(context.Context) ([]*models.Guest, error) {
	return nil, context.DeadlineExceeded
}
