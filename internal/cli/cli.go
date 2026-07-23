package cli

import (
	"context"
	"fmt"
	"io"

	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/proxmox"

	ucli "github.com/urfave/cli/v3"
)

// ConnectRequest is populated by the "guest connect" subcommand
// so the caller can initiate a console session after the CLI returns.
type ConnectRequest struct {
	Guest    *models.Guest
	Instance *models.ProxmoxInstance
}

// Deps holds the dependencies injected into CLI commands.
type Deps struct {
	Repo           db.Repository
	Discoverer     proxmox.DiscovererFactory
	Out            io.Writer
	ErrOut         io.Writer
	ConnectRequest *ConnectRequest
}

// Build returns the root urfave/cli command tree.
// The returned command is designed to be run inside an SSH exec session.
//
// Two central guarantees are enforced here so that every current and future
// command automatically inherits them:
//
//  1. ExitErrHandler is set to a no-op so that urfave/cli never calls
//     os.Exit on the SSH server process when a command fails or an unknown
//     flag is supplied.  Without this, any usage error would kill the daemon.
//
//  2. The root Action and each group command's Action use unknownSubcmdAction
//     so that an unrecognized command name (e.g. "ssh host \"bogus cmd\"")
//     always returns a clear error instead of silently printing help.
func Build(deps *Deps) *ucli.Command {
	return &ucli.Command{
		Name:      "proxpass",
		Usage:     "ProxPass admin CLI",
		Writer:    deps.Out,
		ErrWriter: deps.ErrOut,
		// Prevent urfave/cli from calling os.Exit on usage errors or unknown
		// flags.  We are embedded inside an SSH session; exiting would kill the
		// server process.  With this handler set to a no-op the error is
		// propagated back to the caller (admin.go) which writes it to the SSH
		// channel and closes the session cleanly.
		ExitErrHandler: func(_ context.Context, _ *ucli.Command, _ error) {},
		// Surface a clear error when the user types an unrecognized top-level
		// command.  Without this, urfave/cli would silently print help and
		// return nil, leaving the user with no indication of what went wrong.
		Action: unknownSubcmdAction,
		Commands: []*ucli.Command{
			instanceCmd(deps),
			guestCmd(deps),
			clientCmd(deps),
			groupCmd(deps),
			accessCmd(deps),
			policyCmd(deps),
			adminKeyCmd(deps),
			discoverCmd(deps),
		},
	}
}

// unknownSubcmdAction is the Action used on every command that only dispatches
// to subcommands and has no action of its own (the root command and each
// top-level group such as "guest", "instance", etc.).
//
// urfave/cli v3 invokes the parent command's Action when the user supplies an
// argument that does not match any known subcommand name.  By returning an
// error here — instead of silently printing help — the user always receives a
// clear message such as:
//
//	Error: unknown command "foobar"; run 'proxpass --help' for usage
func unknownSubcmdAction(_ context.Context, cmd *ucli.Command) error {
	if cmd.NArg() > 0 {
		return fmt.Errorf("unknown command %q; run '%s --help' for usage",
			cmd.Args().First(), cmd.FullName())
	}
	// No arguments: fall through to the built-in help output.
	return ucli.ShowSubcommandHelp(cmd)
}
