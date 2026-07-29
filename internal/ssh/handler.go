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
// Routing table:
//
//	Command              Admin                        Client
//	help/--help/-h       CLI --help output            usage message + guest list
//	(none/no PTY)        "need -t" error              "need -t" error
//	(none/PTY)           interactive TUI picker       interactive TUI picker
//	single-token+PTY     direct proxy or CLI          resolve+access+proxy
//	multi-word+PTY       CLI                          "access denied" error
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

	// --- phase 1: negotiate env / pty-req / shell / exec ---
	var execCmd string
	var ptyReq *PtyRequest
	var remaining <-chan *gossh.Request
	// clientEnv holds a small allowlist of SSH env variables sent by the
	// client via "env" channel requests (e.g. OpenSSH SetEnv in ssh_config).
	// We only retain the keys relevant to color-profile detection.
	clientEnv := make(map[string]string)

	for req := range reqs {
		switch req.Type {
		case reqTypeEnv:
			name, value, err := parseEnvRequest(req.Payload)
			if err != nil {
				logger.Printf("%s: bad env req: %v", si.logLabel, err)
				replyReq(req, false)
				continue
			}
			switch name {
			case "TERM", "COLORTERM", "NO_COLOR", "PROXPASS_DISABLE_STATUSBAR":
				clientEnv[name] = value
			}
			replyReq(req, true)

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
	// Apply all accumulated SSH env vars to ptyReq now that the full negotiation
	// loop has run. We do this at dispatch time (not at pty-req time) so that
	// env requests arriving *after* pty-req (which OpenSSH may do) are included.
	// pty-req TERM takes priority over the env TERM when non-empty.
	if ptyReq != nil {
		if ptyReq.Term == "" {
			ptyReq.Term = clientEnv["TERM"]
		}
		ptyReq.ColorTerm = clientEnv["COLORTERM"]
		ptyReq.NoColor = clientEnv["NO_COLOR"]
		ptyReq.DisableStatusBar = isTruthy(clientEnv["PROXPASS_DISABLE_STATUSBAR"])
	}

	ctx := context.Background()

	// --- phase 2: help is allowed with or without a PTY ---
	if isHelpCommand(execCmd) {
		writeHelp(ctx, channel, repo, logger, discoverer, si)
		drainAndDiscard(remaining)
		return
	}

	// --- phase 3: PTY required for all interactive paths ---
	if failIfNoPtyRequest(channel.Stderr(), ptyReq) {
		logger.Printf("%s: no pty-req; refusing", si.logLabel)
		drainAndDiscard(remaining)
		return
	}

	// --- phase 4: PTY present ---

	// No command: interactive TUI picker (clientID==0 means admin: show all).
	if execCmd == "" {
		interactiveGuestPicker(ctx, si.clientID, channel, remaining, repo, proxier, ptyReq, logger)
		return
	}

	if si.isAdmin {
		runAdminCommand(ctx, execCmd, channel, remaining, repo, proxier, discoverer, ptyReq, logger, si.logLabel)
		return
	}

	// Clients: only single-token guest identifiers are allowed.
	// Multi-word commands look like CLI commands and are explicitly rejected.
	if strings.ContainsRune(execCmd, ' ') {
		logger.Printf("%s: rejected multi-word command %q", si.logLabel, execCmd)
		writeErr(channel, ptyReq, "access denied: clients may only connect to guests")
		drainAndDiscard(remaining)
		return
	}
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

	// If the CLI requested a guest connection ("guest connect ct100"), proxy now.
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
	inName, identifier := cli.ParseGuestTarget(execCmd)

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

	guest, inst, err := cli.ResolveGuestAndInstance(identifier, inName, guests, instances)
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
	inName, identifier := cli.ParseGuestTarget(execCmd)

	guests, err := repo.ListGuests(ctx)
	if err != nil {
		return false, fmt.Errorf("listing guests: %w", err)
	}
	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		return false, fmt.Errorf("listing instances: %w", err)
	}

	guest, inst, err := cli.ResolveGuestAndInstance(identifier, inName, guests, instances)
	if err != nil {
		return false, err
	}

	// Bridge remaining into proxyReqs. The goroutine blocks on send so that
	// no requests (especially window-change) are ever silently dropped.
	proxyReqs := make(chan *gossh.Request, 4)
	go func() {
		for req := range remaining {
			proxyReqs <- req
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
	proxyReqs := make(chan *gossh.Request, 4)
	defer close(proxyReqs)
	if err := proxier.ProxyToGuest(channel, proxyReqs, req.Guest, req.Instance, ptyReq, logger); err != nil {
		logger.Printf("%s: proxy error: %v", logLabel, err)
	}
}

// writeHelp prints usage information to stderr:
//   - Admins: runs "proxpass --help" through the CLI to get the real output.
//   - Clients: prints a static guest-connection usage message + filtered guest list.
//
// Works with or without a PTY.
func writeHelp(
	ctx context.Context,
	channel gossh.Channel,
	repo db.Repository,
	logger *log.Logger,
	discoverer proxmox.DiscovererFactory,
	si sessionInfo,
) {
	w := newCRLFWriter(channel.Stderr())
	if si.isAdmin {
		// Run the real CLI help so it stays in sync with actual commands.
		deps := &cli.Deps{
			Repo:       repo,
			Discoverer: discoverer,
			Out:        w,
			ErrOut:     w,
		}
		_ = cli.Build(deps).Run(ctx, []string{"proxpass", "--help"})
		return
	}
	// Clients: static message + their filtered guest list.
	_, _ = fmt.Fprint(w,
		"Usage: ssh -t <host> [<instance>:]<identifier>\r\n\r\n"+
			"Identifier can be a VMID (e.g. 100), type+VMID (e.g. ct100), or name (e.g. webserver).\r\n"+
			"If multiple guests match, prefix with the instance name (e.g. rome:ct101).\r\n\r\n")
	writeFilteredGuestList(ctx, channel, repo, logger, si)
}

// writeFilteredGuestList fetches and prints the guest table, filtered by
// access for clients. Output goes to w (either stdout or stderr depending
// on the caller). w must already produce \r\n line endings (pass a crlf writer).
func writeFilteredGuestList(
	ctx context.Context,
	w gossh.Channel,
	repo db.Repository,
	logger *log.Logger,
	si sessionInfo,
) {
	crlf := newCRLFWriter(w)

	guests, err := repo.ListGuests(ctx)
	if err != nil {
		logger.Printf("%s: list guests for listing: %v", si.logLabel, err)
		return
	}

	// Filter for clients.
	if !si.isAdmin {
		for i := len(guests) - 1; i >= 0; i-- {
			ok, accessErr := repo.HasAccess(ctx, si.clientID, guests[i].ID)
			if accessErr != nil {
				logger.Printf("%s: access check for listing: %v", si.logLabel, accessErr)
				return
			}
			if !ok {
				guests = append(guests[:i], guests[i+1:]...)
			}
		}
	}

	if len(guests) == 0 {
		_, _ = fmt.Fprint(crlf, "No guests available.\r\n")
		return
	}

	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		logger.Printf("%s: list instances for listing: %v", si.logLabel, err)
		return
	}
	instMap := make(map[int64]string, len(instances))
	for _, inst := range instances {
		instMap[inst.ID] = inst.Name
	}

	_, _ = fmt.Fprintf(crlf, "%-6s %-6s %-24s %-10s %s\r\n",
		"TYPE", "VMID", "NAME", "STATUS", "INSTANCE")
	for _, g := range guests {
		instName := instMap[g.InstanceID]
		if instName == "" {
			instName = fmt.Sprintf("(id:%d)", g.InstanceID)
		}
		_, _ = fmt.Fprintf(crlf, "%-6s %-6d %-24s %-10s %s\r\n",
			g.Type, g.ProxmoxID, g.Name, g.Status, instName)
	}
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
