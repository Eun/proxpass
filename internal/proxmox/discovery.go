package proxmox

import (
	"context"
	"fmt"
	"log"
	"time"

	"proxpass/internal/db"
	"proxpass/internal/models"
)

// Discovery periodically polls all registered Proxmox instances, discovers
// their guests, and upserts the results into the database.
type Discovery struct {
	repo              db.Repository
	interval          time.Duration
	logger            *log.Logger
	discovererFactory DiscovererFactory
}

// NewDiscovery creates a new Discovery loop.
func NewDiscovery(repo db.Repository, interval time.Duration, logger *log.Logger, factory DiscovererFactory) *Discovery {
	return &Discovery{
		repo:              repo,
		interval:          interval,
		logger:            logger,
		discovererFactory: factory,
	}
}

// Run starts the periodic discovery loop. It blocks until ctx is canceled.
// Intended to be launched in a goroutine.
func (d *Discovery) Run(ctx context.Context) {
	d.logger.Printf("discovery: starting loop (interval %s)", d.interval)

	// Run immediately on start, then on each tick.
	if err := d.RunOnce(ctx); err != nil {
		d.logger.Printf("discovery: initial pass error: %v", err)
	}

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.logger.Printf("discovery: stopped")
			return
		case <-ticker.C:
			if err := d.RunOnce(ctx); err != nil {
				d.logger.Printf("discovery: pass error: %v", err)
			}
		}
	}
}

// RunOnce performs a single discovery pass across all Proxmox instances.
func (d *Discovery) RunOnce(ctx context.Context) error {
	instances, err := d.repo.ListProxmoxInstances(ctx)
	if err != nil {
		return fmt.Errorf("list proxmox instances: %w", err)
	}

	if len(instances) == 0 {
		d.logger.Printf("discovery: no proxmox instances configured")
		return nil
	}

	var lastErr error
	for _, inst := range instances {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := d.discoverInstance(ctx, inst); err != nil {
			d.logger.Printf("discovery: instance %s (id=%d): %v", inst.Name, inst.ID, err)
			lastErr = err
		}
	}
	return lastErr
}

// discoverInstance connects to a single Proxmox host, discovers its guests,
// and upserts them into the database.
func (d *Discovery) discoverInstance(ctx context.Context, inst *models.ProxmoxInstance) error {
	discoverer := d.discovererFactory(inst)

	guests, err := discoverer.DiscoverGuests(ctx)
	if err != nil {
		return fmt.Errorf("discover guests on %s: %w", inst.Name, err)
	}

	d.logger.Printf("discovery: instance %s: found %d guests", inst.Name, len(guests))

	for _, g := range guests {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Only store running guests: stopped guests cannot be entered via
		// pct enter / qm terminal, so there is no point surfacing them.
		if g.Status != models.StatusRunning {
			continue
		}
		g.InstanceID = inst.ID
		if err := d.repo.UpsertGuest(ctx, g); err != nil {
			d.logger.Printf("discovery: upsert guest %s (proxmox_id=%d): %v", g.Name, g.ProxmoxID, err)
		}
	}

	return nil
}
