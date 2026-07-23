package ssh

import (
	"log"

	"proxpass/internal/models"

	gossh "golang.org/x/crypto/ssh"
)

// GuestProxier proxies an SSH channel to a Proxmox guest console.
type GuestProxier interface {
	ProxyToGuest(
		clientChan gossh.Channel,
		clientReqs <-chan *gossh.Request,
		guest *models.Guest,
		inst *models.ProxmoxInstance,
		pty *PtyRequest,
		logger *log.Logger,
	) error
}

// DefaultProxier is the default implementation that connects to
// the Proxmox host via SSH and runs pct enter / qm terminal.
type DefaultProxier struct{}

// ProxyToGuest implements GuestProxier by dispatching to either the
// termproxy WebSocket path or the legacy SSH path depending on
// inst.ConnectionType.
func (DefaultProxier) ProxyToGuest(
	clientChan gossh.Channel,
	clientReqs <-chan *gossh.Request,
	guest *models.Guest,
	inst *models.ProxmoxInstance,
	pty *PtyRequest,
	logger *log.Logger,
) error {
	if inst.ConnectionType == models.ConnectionTypeTermProxy {
		return proxyViaTermProxy(clientChan, clientReqs, guest, inst, pty, logger)
	}
	return proxyToGuest(clientChan, clientReqs, guest, inst, pty, logger)
}
