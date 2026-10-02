package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

// ClientDeps holds what a client-scoped CLI needs on top of Deps.
type ClientDeps struct {
	*Deps

	// Guests is the set of guests this client may reach, already filtered
	// by the caller.
	//
	// It is passed in rather than looked up because the filtering lives in
	// the session, which owns the access rules. Taking the pool as a
	// parameter also makes the scoping structural: no command in this tree
	// can widen it, because none of them can see anything else.
	Guests []*models.Guest

	// Instances are the Proxmox instances; only those hosting one of
	// Guests are ever named in output.
	Instances []*models.ProxmoxInstance
}

// BuildClient returns the command tree a non-admin client may run.
//
// This is deliberately a SEPARATE, much smaller tree rather than the admin
// CLI with commands hidden. Filtering a shared tree would mean every
// command added for admins is reachable by clients until someone remembers
// to exclude it; here the default is that nothing is exposed.
//
// Every command operates on the pre-filtered guest pool, so a client cannot
// see or reach a guest its access rules do not allow -- including through
// "ls", which lists exactly what the picker would show.
func BuildClient(deps *ClientDeps) *ucli.Command {
	return &ucli.Command{
		Name:      "proxpass",
		Usage:     "ProxPass client CLI",
		Writer:    deps.Out,
		ErrWriter: deps.ErrOut,
		// As in Build: never let urfave/cli call os.Exit, since this runs
		// inside the session process.
		ExitErrHandler: func(_ context.Context, _ *ucli.Command, _ error) {},
		Action:         unknownSubcmdAction,
		Commands: []*ucli.Command{
			{
				Name:   "guest",
				Usage:  "List and connect to the guests you may reach",
				Action: unknownSubcmdAction,
				Commands: []*ucli.Command{
					{
						Name:  cmdLs,
						Usage: "List the guests you may reach",
						Flags: []ucli.Flag{
							&ucli.StringFlag{
								Name: flagFormat, Value: formatPlain, Usage: usageFormat,
							},
						},
						Action: func(_ context.Context, cmd *ucli.Command) error {
							return clientGuestLs(deps, cmd)
						},
					},
					{
						Name:      cmdConnect,
						Usage:     "Connect to a guest's console",
						ArgsUsage: "<identifier>[@<instance>]",
						Action: func(_ context.Context, cmd *ucli.Command) error {
							return clientGuestConnect(deps, cmd)
						},
					},
				},
			},
		},
	}
}

// clientGuestLs prints the guests this client may reach.
func clientGuestLs(deps *ClientDeps, cmd *ucli.Command) error {
	if cmd.String(flagFormat) == formatJSON {
		return json.NewEncoder(deps.Out).Encode(deps.Guests)
	}
	if len(deps.Guests) == 0 {
		_, err := fmt.Fprintln(deps.Out, "No guests available.")
		return err
	}
	instNames := make(map[int64]string, len(deps.Instances))
	for _, inst := range deps.Instances {
		instNames[inst.ID] = inst.Name
	}
	w := tabwriter.NewWriter(deps.Out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TYPE\tVMID\tNAME\tSTATUS\tINSTANCE")
	for _, g := range deps.Guests {
		_, _ = fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n",
			g.Type, g.ProxmoxID, g.Name, g.Status, instNames[g.InstanceID])
	}
	return w.Flush()
}

// clientGuestConnect resolves the target and asks the caller to attach.
//
// Resolution runs against the pre-filtered pool, so a guest this client may
// not reach is reported as not found rather than denied -- the same choice
// the login-name path makes, and for the same reason: the identifier is
// caller-supplied and must not become a way to probe for guests.
func clientGuestConnect(deps *ClientDeps, cmd *ucli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf(
			"usage: guest connect <identifier>[@<instance>]\n\n" +
				"identifier can be a VMID (e.g. 100), type+VMID (e.g. ct100), or name (e.g. webserver).\n" +
				"if multiple guests match, qualify it with the instance (e.g. ct101@rome)")
	}
	target := strings.TrimSpace(cmd.Args().First())

	// Only instances hosting a reachable guest count as a qualifier, so the
	// suffix cannot be used to test whether an instance exists.
	visible := make([]*models.ProxmoxInstance, 0, len(deps.Instances))
	hosting := make(map[int64]struct{}, len(deps.Guests))
	for _, g := range deps.Guests {
		hosting[g.InstanceID] = struct{}{}
	}
	for _, inst := range deps.Instances {
		if _, ok := hosting[inst.ID]; ok {
			visible = append(visible, inst)
		}
	}

	instName, identifier := ParseGuestTarget(target, InstanceLookup(visible))
	guest, inst, err := ResolveGuestAndInstance(
		identifier, instName, deps.Guests, deps.Instances)
	if err != nil {
		return err
	}
	deps.ConnectRequest = &ConnectRequest{Guest: guest, Instance: inst}
	return nil
}
