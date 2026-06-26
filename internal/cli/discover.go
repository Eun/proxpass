package cli

import (
	"context"
	"fmt"

	ucli "github.com/urfave/cli/v3"
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
				for _, g := range guests {
					g.InstanceID = inst.ID
					_ = deps.Repo.UpsertGuest(ctx, g)
				}
				fmt.Fprintf(deps.Out, "Instance %q: %d guests discovered.\n", inst.Name, len(guests))
				total += len(guests)
			}
			fmt.Fprintf(deps.Out, "Total: %d guests.\n", total)
			return nil
		},
	}
}
