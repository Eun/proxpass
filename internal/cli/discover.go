package cli

import (
	"context"
	"fmt"

	ucli "github.com/urfave/cli/v3"

	"proxpass/internal/proxmox"
)

func discoverCmd(deps *Deps) *ucli.Command {
	return &ucli.Command{
		Name:  "discover",
		Usage: "Run guest discovery on all instances now",
		Action: func(ctx context.Context, _ *ucli.Command) error {
			if deps.Discoverer == nil {
				return fmt.Errorf("discovery not configured")
			}
			instances, err := deps.Repo.ListProxmoxInstances(ctx)
			if err != nil {
				return err
			}
			if len(instances) == 0 {
				fmt.Fprintln(deps.Out, "No instances configured.")
				return nil
			}
			total := 0
			for _, inst := range instances {
				d := deps.Discoverer(inst)
				guests, err := d.DiscoverGuests(ctx)
				if err != nil {
					fmt.Fprintf(deps.ErrOut, "Instance %q: %v\n", inst.Name, err)
					continue
				}
				// Shared with the background discovery loop so a manual
				// pass produces exactly the same guest list: only running
				// guests are stored, and anything gone is pruned.
				stored, removed, err := proxmox.StoreGuests(ctx, deps.Repo, inst, guests)
				if err != nil {
					fmt.Fprintf(deps.ErrOut, "Instance %q: %v\n", inst.Name, err)
				}
				fmt.Fprintf(deps.Out,
					"Instance %q: %d running guest(s) of %d discovered, %d stale removed.\n",
					inst.Name, stored, len(guests), removed)
				total += stored
			}
			fmt.Fprintf(deps.Out, "Total: %d guests.\n", total)
			return nil
		},
	}
}
