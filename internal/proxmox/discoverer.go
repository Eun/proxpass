package proxmox

import (
	"context"

	"proxpass/internal/models"
)

// GuestDiscoverer discovers guests on a Proxmox instance.
type GuestDiscoverer interface {
	DiscoverGuests(ctx context.Context) ([]*models.Guest, error)
}

// DiscovererFactory creates a GuestDiscoverer for a given Proxmox instance.
type DiscovererFactory func(inst *models.ProxmoxInstance) GuestDiscoverer
