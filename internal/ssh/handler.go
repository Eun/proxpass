package ssh

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"proxpass/internal/cli"
	"proxpass/internal/db"
	"proxpass/internal/proxmox"

	gossh "golang.org/x/crypto/ssh"
)

// sessionInfo holds the identity information derived from the SSH
// connection; it is passed throughout handleSession.
type sessionInfo struct {
	// logLabel is a short string used in log lines (e.g. "admin" or "client/alice").
	logLabel string
	// clientID is the DB id of the authenticated client, or 0 for admins.
	clientID int64
	// isAdmin is true when the connection authenticated with an admin key.
	isAdmin bool
}

// handleSession is the single entry point for every authenticated SSH
// session channel, regardless of whether the connection is an admin or
// a regular client.
//
// Routing logic (same for both roles, access checks inside):
//
//  1. No PTY                        -> fail early with clear error
//  2. help/--help/-h                -> write usage message
//  3. no command (plain shell)      -> interactive TUI picker
//  4. single-token command (admin)  -> try direct guest proxy, fall through to CLI on not-found
//  5. multi-word command (admin)    -> run admin CLI
//  6. single-token command (client) -> resolve guest + access check + proxy
//
//nolint:gocognit,funlen // SSH session handling requires sequential branching
func handleSession(
	channel gossh.Channel,
	reqs <-chan *gossh.Request,
	repo db.Repository,
	proxier GuestProxier,
	discoverer proxmox.DiscovererFactory,
	logger *log.Logger,
	si sessionInfo,
) {
	defer func() { _ = channel.Close() }()

	// --- phase 1: negotiate pty-req / shell / exec ---
	var execCmd string
	var ptyReq *PtyRequest
	var remaining <-chan *gossh.Request

	for req := range reqs {
		switch req.Type {
		case reqTypePTY:
			p, err := parsePtyReq(req.Payload)
			if err != nil {
				logger.Printf("%s: bad pty-req: %v", si.logLabel, err)
				replyReq(req, false)
				continue
			}
			ptyReq = p
			replyReq(req, true)

		case reqTypeExec:
			replyReq(req, true)
			execCmd = parseExecPayload(req.Payload)
			remaining = reqs
			goto dispatch
		case reqTypeShell:
			replyReq(req, true)
			remaining = reqs
			goto dispatch
		default:
			replyReq(req, false)
		}
	}
	return

dispatch:
	ctx := context.Background()

	// --- phase 2: PTY required for all paths ---
	if failIfNoPtyRequest(channel.Stderr(), ptyReq) {
		logger.Printf("%s: no pty-req; refusing", si.logLabel)
		drainAndDiscard(remaining)
		return
	}

	// --- phase 3: help routing ---
	if isHelpCommand(execCmd) {
		writeHelp(ctx, channel, repo, logger, si)
		drainAndDiscard(remaining)
		return
	}

	// --- phase 4: no command = interactive picker ---
	if execCmd == "" {
		// clientID==0 means admin: show all guests.
		interactiveGuestPicker(ctx, si.clientID, channel, remaining, repo, proxier, ptyReq, logger)
		return
	}

	// --- phase 5: admin-only paths ---
	if si.isAdmin {
		runAdminCommand(ctx, execCmd, channel, remaining, repo, proxier, discoverer, ptyReq, logger, si.logLabel)
		return
	}

	// --- phase 6: client direct proxy ---
	runClientProxy(ctx, execCmd, channel, remaining, repo, proxier, ptyReq, logger, si)
}

// runAdminCommand handles an exec command for an admin session.
//
// Single-token commands: try direct guest proxy; on not-found fall through
// to the CLI (so e.g. "zzz123" not matching a guest runs the CLI with that
// arg and produces "unknown command").
// Multi-word commands (e.g. "guest ls"): always run the CLI.
func runAdminCommand(
	ctx context.Context,
	execCmd string,
	channel gossh.Channel,
	remaining <-chan *gossh.Request,
	repo db.Repository,
	proxier GuestProxier,
	discoverer proxmox.DiscovererFactory,
	ptyReq *PtyRequest,
	logger *log.Logger,
	logLabel string,
) {
	// Try direct proxy for single-token commands (no spaces); multi-word goes straight to CLI.
	if !strings.ContainsRune(execCmd, ' ') {
		proxied, err := tryDirectProxy(ctx, execCmd, channel, remaining, repo, proxier, ptyReq, logger, logLabel)
		if proxied {
			return
		}
		if err != nil && !errors.Is(err, &GuestNotFoundError{}) {
			// Looked like a guest ID but could not be resolved (repo error).
			writeErr(channel, ptyReq, fmt.Sprintf("Error: %v", err))
			drainAndDiscard(remaining)
			return
		}
		// Not-found: fall through to CLI so "ssh host zzz999" produces
		// "Error: unknown command" instead of silence.
	}

	// Run the admin CLI.
	drainAndDiscard(remaining)
	out := newCRLFWriter(channel)
	errOut := newCRLFWriter(channel.Stderr())
	deps := &cli.Deps{
		Repo:       repo,
		Discoverer: discoverer,
		Out:        out,
		ErrOut:     errOut,
	}
	argv := append([]string{"proxpass"}, splitArgs(execCmd)...)
	if err := cli.Build(deps).Run(ctx, argv); err != nil {
		_, _ = fmt.Fprintf(channel.Stderr(), "Error: %v\r\n", err)
	}

	// if the CLI requested a guest connection ("guest connect ct100"), proxy now.
	if deps.ConnectRequest != nil {
		proxyAfterCLI(channel, proxier, ptyReq, logger, logLabel, deps.ConnectRequest)
	}
}

// runClientProxy resolves the exec command as a guest identifier, checks
// access, and proxies the channel.
func runClientProxy(
	ctx context.Context,
	execCmd string,
	channel gossh.Channel,
	remaining <-chan *gossh.Request,
	repo db.Repository,
	proxier GuestProxier,
	ptyReq *PtyRequest,
	logger *log.Logger,
	si sessionInfo,
) {
	instName, identifier := cli.ParseGuestTarget(execCmd)

	guests, err := repo.ListGuests(ctx)
	if err != nil {
		logger.Printf("%s: failed to list guests: %v", si.logLabel, err)
		writeErr(channel, ptyReq, "internal error")
		drainAndDiscard(remaining)
		return
	}

	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		logger.Printf("%s: failed to list instances: %v", si.logLabel, err)
		writeErr(channel, ptyReq, "internal error")
		drainAndDiscard(remaining)
		return
	}

	guest, inst, err := cli.ResolveGuestAndInstance(identifier, instName, guests, instances)
	if err != nil {
		logger.Printf("%s: %v", si.logLabel, err)
		writeErr(channel, ptyReq, err.Error())
		drainAndDiscard(remaining)
		return
	}

	ok, err := repo.HasAccess(ctx, si.clientID, guest.ID)
	if err != nil {
		logger.Printf("%s: access check failed: %v", si.logLabel, err)
		writeErr(channel, ptyReq, "internal error")
		drainAndDiscard(remaining)
		return
	}
	if !ok {
		logger.Printf("%s: access denied to guest %s", si.logLabel, guest.Name)
		writeErr(channel, ptyReq, "access denied")
		drainAndDiscard(remaining)
		return
	}

	if err := proxier.ProxyToGuest(channel, remaining, guest, inst, ptyReq, logger); err != nil {
		logger.Printf("%s: proxy error: %v", si.logLabel, err)
		writeErr(channel, ptyReq, fmt.Sprintf("proxy error: %v", err))
	}
}

// tryDirectProxy attempts to resolve execCmd as a guest identifier and proxy.
// proxied=true means caller must return.
// (proxied=false, err=nil) means not-found; fall through to CLI.
// (proxied=false, err!=nil) means repo error; caller should report and return.
func tryDirectProxy(
	ctx context.Context,
	execCmd string,
	channel gossh.Channel,
	remaining <-chan *gossh.Request,
	repo db.Repository,
	proxier GuestProxier,
	ptyReq *PtyRequest,
	logger *log.Logger,
	logLabel string,
) (proxied bool, err error) {
	instName, identifier := cli.ParseGuestTarget(execCmd)

	guests, err := repo.ListGuests(ctx)
	if err != nil {
		return false, fmt.Errorf("listing guests: %w", err)
	}
	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		return false, fmt.Errorf("listing instances: %w", err)
	}

	guest, inst, err := cli.ResolveGuestAndInstance(identifier, instName, guests, instances)
	if err != nil {
		return false, err
	}

	// Forward remaining SSH requests via a buffered bridge channel so they
	// don't block while proxyToGuest is running.
	proxyReqs := make(chan *gossh.Request, 4)
	go func() {
		for req := range remaining {
			select {
			case proxyReqs <- req:
			default:
				replyReq(req, false)
			}
		}
		close(proxyReqs)
	}()

	if proxyErr := proxier.ProxyToGuest(channel, proxyReqs, guest, inst, ptyReq, logger); proxyErr != nil {
		logger.Printf("%s: proxy to guest %q error: %v", logLabel, guest.Name, proxyErr)
	}
	return true, nil
}

// proxyAfterCLI proxies to a guest after the admin CLI has run and set
// a ConnectRequest (e.g. via "guest connect ct100").
func proxyAfterCLI(
	channel gossh.Channel,
	proxier GuestProxier,
	ptyReq *PtyRequest,
	logger *log.Logger,
	logLabel string,
	req *cli.ConnectRequest,
) {
	_, _ = fmt.Fprintf(newCRLFWriter(channel), "Connecting to %s (%s %d)...\r\n",
		req.Guest.Name, req.Guest.Type, req.Guest.ProxmoxID)
	proxyReqs := make(chan *gossh.Request, 4)
	defer close(proxyReqs)
	if err := proxier.ProxyToGuest(channel, proxyReqs, req.Guest, req.Instance, ptyReq, logger); err != nil {
		logger.Printf("%s: proxy error: %v", logLabel, err)
	}
}

// writeHelp prints role-aware usage information and a guest list to stderr.
func writeHelp(ctx context.Context, channel gossh.Channel, repo db.Repository, logger *log.Logger, si sessionInfo) {
	w := newCRLFWriter(channel.Stderr())
	if si.isAdmin {
		_, _ = fmt.Fprint(w,
			"Usage: ssh -t <host> [<guest-identifier>]\r\n\r\n"+
				"Pass a single guest identifier (e.g. ct100, rome:ct101) to connect directly.\r\n"+
				"Omit the identifier to see the interactive guest picker.\r\n"+
				"Pass a CLI command (e.g. 'guest ls', 'instance ls') to manage proxpass.\r\n\r\n")
	} else {
		_, _ = fmt.Fprint(w,
			"Usage: ssh -t <host> [<instance>:]<identifier>\r\n\r\n"+
				"Identifier can be a VMID (e.g. 100), type+VMID (e.g. ct100), or name (e.g. webserver).\r\n"+
				"If multiple guests match, prefix with the instance name (e.g. rome:ct101).\r\n\r\n")
	}
	writeGuestList(ctx, w, repo, logger, si.logLabel)
}

// --- small helpers ---

// replyReq sends a WantReply response if needed.
func replyReq(req *gossh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

// parseExecPayload extracts the command string from an SSH exec request
// payload (RFC 4254 §6.5: uint32 len + UTF-8 string).
func parseExecPayload(p []byte) string {
	if len(p) < 4 {
		return ""
	}
	cmdLen := int(p[0])<<24 | int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	if len(p) < 4+cmdLen {
		return ""
	}
	return string(p[4 : 4+cmdLen])
}

// drainAndDiscard replies false to all pending requests and drains the channel.
func drainAndDiscard(remaining <-chan *gossh.Request) {
	go gossh.DiscardRequests(remaining)
}
