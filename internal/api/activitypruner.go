package api

import (
	"context"
	"log"
	"time"

	"proxpass/internal/db"
)

// ActivityPruner enforces activity-log retention: it periodically deletes rows
// older than the retention window. It runs in serve (the DB-holding process),
// alongside discovery.
//
// When retention is zero, activity logging is disabled, so the pruner is a
// no-op -- Run returns immediately. The cadence is independent of the window:
// pruning hourly keeps the table bounded without a tight loop, the same shape
// as the discovery poller.
type ActivityPruner struct {
	repo      db.Repository
	retention time.Duration
	interval  time.Duration
	logger    *log.Logger
}

// activityPruneInterval is how often retention is enforced. Hourly: the table
// only needs to be kept roughly bounded, not trimmed to the second.
const activityPruneInterval = time.Hour

// NewActivityPruner builds a pruner. A zero retention disables it.
func NewActivityPruner(repo db.Repository, retention time.Duration, logger *log.Logger) *ActivityPruner {
	return &ActivityPruner{
		repo:      repo,
		retention: retention,
		interval:  activityPruneInterval,
		logger:    logger,
	}
}

// Run prunes once immediately, then every interval, until ctx is cancelled.
// A no-op when retention is zero (logging disabled).
func (p *ActivityPruner) Run(ctx context.Context) {
	if p.retention <= 0 {
		return
	}
	p.pruneOnce(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			p.logger.Printf("activity: retention pruner stopped")
			return
		case <-ticker.C:
			p.pruneOnce(ctx)
		}
	}
}

// pruneOnce deletes rows older than the retention window, best-effort.
func (p *ActivityPruner) pruneOnce(ctx context.Context) {
	cutoff := time.Now().Add(-p.retention)
	removed, err := p.repo.DeleteActivityOlderThan(ctx, cutoff)
	if err != nil {
		p.logger.Printf("activity: pruning old events failed: %v", err)
		return
	}
	if removed > 0 {
		p.logger.Printf("activity: pruned %d event(s) older than %s", removed, p.retention)
	}
}
