package cli

import (
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
func Build(deps *Deps) *ucli.Command {
	return &ucli.Command{
		Name:  "proxpass",
		Usage: "ProxPass admin CLI",
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
