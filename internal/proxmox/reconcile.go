package proxmox

import (
	"context"
	"fmt"

	"proxpass/internal/db"
	"proxpass/internal/models"
)

// StoreGuests writes the result of a discovery pass for one instance and
// prunes whatever it did not report.
//
// It is the single place that decides what ends up in the guest list, because
// having more than one made them disagree: the background discovery loop
// skipped stopped guests and pruned stale rows, while "proxpass discover" and
// "instance add" upserted every guest and never pruned. A guest stopped after
// an "instance add" therefore stayed in the picker forever and failed at
// connect time.
//
// Only running guests are stored: pct enter and qm terminal both need a
// running guest, so a stopped one is not connectable and has nothing to offer.
//
// Pruning is safe because DiscoverGuests is all-or-nothing — the caller must
// not call this with a partial list, or the missing guests are deleted.
func StoreGuests(
	ctx context.Context,
	repo db.Repository,
	inst *models.ProxmoxInstance,
	guests []*models.Guest,
) (stored, removed int, err error) {
	// live collects the vmids this pass considers connectable, so that
	// anything else belonging to this instance can be pruned afterwards.
	live := make([]int, 0, len(guests))

	var firstErr error
	for _, g := range guests {
		if err := ctx.Err(); err != nil {
			return stored, 0, err
		}
		if g.Status != models.StatusRunning {
			continue
		}
		g.InstanceID = inst.ID
		if err := repo.UpsertGuest(ctx, g); err != nil {
			// Keep going, but treat the guest as live: a transient write
			// error must not delete a guest that is still running.
			if firstErr == nil {
				firstErr = fmt.Errorf("upsert guest %s (proxmox_id=%d): %w",
					g.Name, g.ProxmoxID, err)
			}
			live = append(live, g.ProxmoxID)
			continue
		}
		live = append(live, g.ProxmoxID)
		stored++
	}

	removed, err = repo.RemoveGuestsNotIn(ctx, inst.ID, live)
	if err != nil {
		return stored, 0, fmt.Errorf("prune stale guests on %s: %w", inst.Name, err)
	}
	return stored, removed, firstErr
}
