package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"proxpass/internal/models"
	"proxpass/internal/proxmox"
	"proxpass/internal/sshhostkey"

	ucli "github.com/urfave/cli/v3"
)

func instanceCmd(deps *Deps) *ucli.Command { //nolint:gocognit,funlen // CLI command tree
	return &ucli.Command{
		Name:   "instance",
		Usage:  "Manage Proxmox instances",
		Action: unknownSubcmdAction,
		Commands: []*ucli.Command{
			{
				Name:  cmdLs,
				Usage: "List Proxmox instances",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					return listInstances(ctx, deps, cmd.String(flagFormat))
				},
			},
			{
				Name:  cmdAdd,
				Usage: "Add a Proxmox instance",
				Description: `Adds one Proxmox instance to proxpass.

  - --name optionally overrides the automatically resolved node name.
  - --ssh-host optionally sets the SSH host/port for node shell, SFTP and
    file transfer. Accepts "host" or "host:port" (port defaults to 22). It is
    NOT derived from --url; when omitted the instance has no SSH host and those
    features stay disabled until you set one with "instance update --ssh-host".
    The termproxy console works either way.`,
				Flags: []ucli.Flag{
					&ucli.StringFlag{
						Name:  flagName,
						Usage: "Instance name (if omitted the Proxmox node name is used)",
					},
					&ucli.StringFlag{
						Name:     "url",
						Required: true,
						Usage:    "Proxmox API URL (e.g. https://pve:8006)",
					},
					&ucli.StringFlag{Name: "token-id", Required: true, Usage: "API token ID (e.g. user@pam!token)"},
					&ucli.StringFlag{Name: "token-secret", Required: true, Usage: "API token secret"},
					&ucli.BoolFlag{
						Name: flagInsecureTLS,
						Usage: "Skip TLS certificate verification for this instance's" +
							" Proxmox API and console. Needed for a host serving a" +
							" self-signed certificate. Off by default.",
					},
					&ucli.BoolFlag{
						Name: flagInsecureSSH,
						Usage: "Skip SSH host-key verification for this instance's node" +
							" connections (node shell, SFTP, file transfer). Off by" +
							" default; prefer --ssh-fingerprint or SSHFP.",
					},
					&ucli.BoolFlag{
						Name: flagInsecure,
						Usage: "Shorthand for both --insecure-tls and --insecure-ssh:" +
							" skip all verification for this instance.",
					},
					&ucli.StringFlag{
						Name: "ssh-fingerprint",
						Usage: "Pin the node's SSH host key as \"SHA256:<base64>\"" +
							" (the form ssh-keyscan prints). When omitted the host" +
							" key is verified against DNSSEC-validated SSHFP records;" +
							" if none exist the add fails and prints the fingerprint" +
							" to pin here.",
					},
					&ucli.StringFlag{
						Name:  "console-transport",
						Value: string(models.ConsoleTransportTermProxy),
						Usage: `How a guest CONSOLE is attached: "termproxy" ` +
							`(default) or "ssh". Does not affect file ` +
							`transfer, which always reaches the node over SSH.`,
					},
					&ucli.StringFlag{
						Name: "ssh-host",
						Usage: "SSH host — \"host\" or \"host:port\"." +
							" Enables node shell, SFTP and file transfer; not derived" +
							" from --url, so when omitted the instance has no SSH host.",
					},
					&ucli.StringFlag{Name: "ssh-user", Value: "root", Usage: "SSH username"},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					rawURL := cmd.String("url")

					connType := models.ConsoleTransport(cmd.String("console-transport"))
					if connType != models.ConsoleTransportTermProxy && connType != models.ConsoleTransportSSH {
						return fmt.Errorf("--console-transport must be %q or %q", models.ConsoleTransportTermProxy, models.ConsoleTransportSSH)
					}

					if err := validateAPIURL(rawURL); err != nil {
						return err
					}

					// Validate --ssh-host up-front.
					if cmd.String("ssh-host") != "" {
						if _, _, err := parseHostPort(cmd.String("ssh-host"), 22); err != nil {
							return fmt.Errorf("invalid --ssh-host: %w", err)
						}
					}

					// The deployment's own key lives in a root-owned file this
					// session cannot read. Its public half, and the reachability
					// check that needs the private half, are obtained from
					// `proxpass serve' (root) through deps.SSHKeys inside
					// addInstance -- not read here. Instances no longer carry a key
					// of their own: its public half has to be installed on the
					// Proxmox host by hand, and a key per instance multiplies that
					// work without isolating anything.
					return addInstance(ctx, deps, cmd, connType, rawURL)
				},
			},
			{
				Name:  cmdRm,
				Usage: "Remove a Proxmox instance",
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagName, Required: true, Usage: "Instance name"},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					name := cmd.String("name")
					instances, err := deps.Repo.ListProxmoxInstances(ctx)
					if err != nil {
						return err
					}
					for _, inst := range instances {
						// Case-insensitive, matching InstanceLookup and the
						// way an instance resolves inside a login name: it
						// would be odd for `access grant --instance ROME' to
						// work while `instance rm ROME' did not.
						if models.NamesEqual(inst.Name, name) {
							if err := deps.Repo.RemoveProxmoxInstance(ctx, inst.ID); err != nil {
								return err
							}
							fmt.Fprintf(deps.Out, "Instance %q removed.\n", inst.Name)
							return nil
						}
					}
					return fmt.Errorf("instance %q not found", name)
				},
			},
			instanceUpdateCmd(deps),
			{
				Name:      cmdInspect,
				Usage:     "Show details for one or more instances",
				ArgsUsage: argsNames,
				Flags: []ucli.Flag{
					&ucli.StringFlag{Name: flagFormat, Value: formatPlain, Usage: usageFormat},
				},
				Action: func(ctx context.Context, cmd *ucli.Command) error {
					if cmd.NArg() == 0 {
						return fmt.Errorf("usage: instance inspect <name> [<name> ...]")
					}
					instances, err := deps.Repo.ListProxmoxInstances(ctx)
					if err != nil {
						return err
					}
					byName := make(map[string]*models.ProxmoxInstance, len(instances))
					for _, inst := range instances {
						byName[models.FoldName(inst.Name)] = inst
					}
					var found []*models.ProxmoxInstance
					for _, name := range cmd.Args().Slice() {
						inst, ok := byName[models.FoldName(name)]
						if !ok {
							return fmt.Errorf("instance %q not found", name)
						}
						found = append(found, inst)
					}
					if cmd.String(flagFormat) == formatJSON {
						return json.NewEncoder(deps.Out).Encode(found)
					}
					for i, inst := range found {
						if i > 0 {
							fmt.Fprintln(deps.Out)
						}
						inspectInstance(ctx, deps, inst)
					}
					return nil
				},
			},
		},
	}
}

// listInstances renders `instance ls`. It is deliberately a pure database
// read: it shows what is CONFIGURED for each instance, never probing the
// network. Use `instance inspect` to test whether TLS and SSH actually work.
func listInstances(ctx context.Context, deps *Deps, format string) error {
	instances, err := deps.Repo.ListProxmoxInstances(ctx)
	if err != nil {
		return err
	}
	if format == formatJSON {
		return json.NewEncoder(deps.Out).Encode(instances)
	}
	if len(instances) == 0 {
		fmt.Fprintln(deps.Out, "No instances configured.")
		return nil
	}
	for _, inst := range instances {
		fmt.Fprintf(deps.Out, "%-20s  API: %s  TLS: %s  node: %s  %s\n",
			inst.Name, inst.APIURL, configuredTLS(inst), inst.Node, configuredSSH(inst))
	}
	return nil
}

// configuredTLS summarizes an instance's TLS configuration for `instance ls`,
// from stored fields only. "off" means the API URL is plain http, so no TLS is
// in use at all.
func configuredTLS(inst *models.ProxmoxInstance) string {
	if !strings.HasPrefix(strings.ToLower(inst.APIURL), "https://") {
		return "off (http)"
	}
	if inst.InsecureTLS {
		return statusInsecure
	}
	return statusVerified
}

// configuredSSH summarizes an instance's SSH configuration for `instance ls`,
// from stored fields only: whether a host is set and how the host key would be
// verified. It does not say whether SSH actually works.
func configuredSSH(inst *models.ProxmoxInstance) string {
	if inst.SSHHost == "" {
		return "SSH: not configured"
	}
	var verify string
	switch {
	case inst.InsecureSSH:
		verify = statusInsecure
	case inst.SSHFingerprint != "":
		verify = "pinned"
	default:
		verify = "sshfp"
	}
	return fmt.Sprintf("SSH: %s:%d (%s)", inst.SSHHost, inst.SSHPort, verify)
}

// inspectInstance prints the full detail for one instance, including LIVE
// probes: unlike `instance ls`, it tests whether TLS and SSH actually work.
func inspectInstance(ctx context.Context, deps *Deps, inst *models.ProxmoxInstance) {
	fmt.Fprintf(deps.Out, "Name:             %s\n", inst.Name)
	fmt.Fprintf(deps.Out, "API URL:          %s\n", inst.APIURL)
	fmt.Fprintf(deps.Out, "TLS:              %s\n", tlsStatus(inst.InsecureTLS))
	fmt.Fprintf(deps.Out, "TLS Connection:   %s\n", probeTLS(ctx, inst))
	fmt.Fprintf(deps.Out, "API Token ID:     %s\n", inst.APITokenID)
	fmt.Fprintf(deps.Out, "API Token Secret: %s\n", inst.APITokenSecret)
	fmt.Fprintf(deps.Out, "Connection Type:  %s\n", inst.ConsoleTransport)
	fmt.Fprintf(deps.Out, "Node:             %s\n", inst.Node)

	// SSH reaches the node for shell, SFTP and file transfer regardless of the
	// console transport, so report it whenever a host is configured -- not only
	// for the ssh console transport.
	if inst.SSHHost == "" {
		fmt.Fprintf(deps.Out, "SSH:              not configured (set one with `instance update --ssh-host')\n")
		return
	}
	fmt.Fprintf(deps.Out, "SSH Host:         %s\n", inst.SSHHost)
	fmt.Fprintf(deps.Out, "SSH Port:         %d\n", inst.SSHPort)
	fmt.Fprintf(deps.Out, "SSH User:         %s\n", inst.SSHUser)
	fmt.Fprintf(deps.Out, "SSH Host Key:     %s\n", sshHostKeyStatus(inst.InsecureSSH, inst.SSHFingerprint))
	reportSSHKey(ctx, deps, inst)
}

// probeTLS makes a live, classified Proxmox API request and renders whether TLS
// (and the rest of the API handshake) actually works for this instance. A plain
// http API URL is reported as "not in use". The probe honors the instance's
// InsecureTLS setting, so an insecure instance reports ok once reachable.
func probeTLS(ctx context.Context, inst *models.ProxmoxInstance) string {
	if !strings.HasPrefix(strings.ToLower(inst.APIURL), "https://") {
		return "not in use (http API URL)"
	}
	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		return fmt.Sprintf("FAILED: %v", err)
	}
	res := client.CheckAPIConnection(ctx)
	switch res.Status {
	case proxmox.APIConnectionOK:
		return "ok"
	case proxmox.APIConnectionCertError:
		return fmt.Sprintf("FAILED: certificate not trusted "+
			"(add with --insecure-tls or install a trusted certificate): %v", res.Err)
	case proxmox.APIConnectionAuthError:
		return fmt.Sprintf("TLS ok, but the API token was rejected: %v", res.Err)
	case proxmox.APIConnectionUnreachable:
		return fmt.Sprintf("host unreachable: %v", res.Err)
	case proxmox.APIConnectionError:
		return fmt.Sprintf("FAILED: %v", res.Err)
	default:
		return fmt.Sprintf("FAILED: %v", res.Err)
	}
}

// parseExplicitSSHHost parses the SSH host and port from an explicit
// --ssh-host value. An empty value yields an empty host and a zero port,
// deliberately: the SSH host is NEVER derived from --url, because the API URL
// is just as often a bare IP or an address that does not resolve from where
// proxpass runs. An instance with no SSH host is a valid, handled state --
// its termproxy console still works, and node shell / SFTP / file transfer
// are cleanly refused until an admin sets a host with `instance update
// --ssh-host`.
//
// A non-empty value is parsed as "host" or "host:port"; the port defaults to
// 22 when omitted.
func parseExplicitSSHHost(explicitSSHHost string) (host string, port int, err error) {
	if explicitSSHHost == "" {
		return "", 0, nil
	}
	h, p, parseErr := parseHostPort(explicitSSHHost, 22)
	if parseErr != nil {
		return "", 0, fmt.Errorf("invalid --ssh-host: %w", parseErr)
	}
	return h, p, nil
}

// tlsStatus renders an instance's TLS verification setting for display.
func tlsStatus(insecure bool) string {
	if insecure {
		return "insecure (certificate verification disabled)"
	}
	return statusVerified
}

// sshHostKeyStatus renders how an instance's SSH host key is verified for
// display: insecure (not verified), a pinned fingerprint, or the SSHFP
// fallback when none is pinned.
func sshHostKeyStatus(insecure bool, fingerprint string) string {
	if insecure {
		return "insecure (host-key verification disabled)"
	}
	if fingerprint == "" {
		return "(none pinned; verified via DNS SSHFP)"
	}
	return fingerprint
}

// addInstance adds the Proxmox instance described by the "instance add" flags.
func addInstance(
	ctx context.Context,
	deps *Deps,
	cmd *ucli.Command,
	connType models.ConsoleTransport,
	rawURL string,
) error {
	// Determine the SSH host and port.
	//
	// --ssh-host "host" or "host:port" is used as-is. When it is omitted the
	// instance has no SSH host at all: it is NEVER derived from --url, because
	// the API address is just as often a bare IP or an alias that does not
	// resolve from where proxpass runs. The termproxy console works without
	// it; node shell / SFTP / file transfer are cleanly refused until an admin
	// sets a host with `instance update --ssh-host`.
	sshHost, sshPort, err := parseExplicitSSHHost(cmd.String("ssh-host"))
	if err != nil {
		return err
	}

	// A pinned SSH host-key fingerprint, if the administrator supplied one.
	// Validated here so a malformed value is rejected before anything is
	// stored. When empty, the host key is verified against DNSSEC-validated
	// SSHFP records instead.
	var sshFingerprint string
	if fp := cmd.String("ssh-fingerprint"); fp != "" {
		sshFingerprint, err = sshhostkey.NormalizeFingerprint(fp)
		if err != nil {
			return err
		}
	}

	// Resolve the node name from the API.
	// Pass only the bare hostname as the hint (no port) so ResolveNodeName
	// can match it against the cluster node list correctly.
	nodeName, err := resolveInstanceNode(ctx, rawURL, cmd.String("token-id"), cmd.String("token-secret"), sshHost)
	if err != nil {
		return fmt.Errorf("resolving node name for %s: %w", rawURL, err)
	}

	// For termproxy, verify the Proxmox version supports API token auth.
	// This check runs once at instance-add time so the user gets a clear
	// error immediately rather than at connection time.
	if connType == models.ConsoleTransportTermProxy {
		if err := checkTermProxyVersion(ctx, rawURL, cmd.String("token-id"), cmd.String("token-secret")); err != nil {
			return err
		}
	}

	instName := cmd.String(flagName)
	if instName == "" {
		// Name was not supplied: fall back to the resolved node name.
		instName = nodeName
	}

	inst := &models.ProxmoxInstance{
		Name:             instName,
		APIURL:           rawURL,
		APITokenID:       cmd.String("token-id"),
		APITokenSecret:   cmd.String("token-secret"),
		ConsoleTransport: connType,
		Node:             nodeName,
		// --insecure is shorthand for both; --insecure-tls / --insecure-ssh
		// toggle each independently.
		InsecureTLS:    cmd.Bool(flagInsecure) || cmd.Bool(flagInsecureTLS),
		InsecureSSH:    cmd.Bool(flagInsecure) || cmd.Bool(flagInsecureSSH),
		SSHHost:        sshHost,
		SSHPort:        sshPort,
		SSHUser:        cmd.String("ssh-user"),
		SSHFingerprint: sshFingerprint,
	}

	// Check that the key actually opens the host BEFORE storing anything,
	// so a mistake is reported against the command that made it rather than
	// against the first guest somebody tries to reach.
	//
	// A failure is NOT fatal, and that is deliberate: the administrator has
	// to install the public key on the host by hand, and they cannot do that
	// before an instance exists to tell them which host. Refusing here would
	// make the obvious order impossible. So it prints the key and what to do
	// with it, and adds the instance anyway.
	if connType == models.ConsoleTransportSSH && inst.SSHHost != "" {
		if err := probeSSHAccessBeforeAdd(ctx, deps, inst, instName); err != nil {
			return err
		}
	}

	if err := deps.Repo.AddProxmoxInstance(ctx, inst); err != nil {
		return err
	}
	fmt.Fprintf(deps.Out, "Instance %q added (connection: %s, node: %s).\n", inst.Name, inst.ConsoleTransport, inst.Node)

	// Warn when there is no SSH host: the instance was still added (its console
	// may work), but node shell, SFTP and file transfer are unavailable until
	// a host is set. No-op when a host is present.
	warnMissingSSHHost(ctx, deps, inst)

	// Run discovery on the new instance.
	if deps.Discoverer != nil {
		// Re-read to get the DB-assigned ID.
		allInstances, err := deps.Repo.ListProxmoxInstances(ctx)
		if err != nil {
			return nil // non-fatal
		}
		for _, i := range allInstances {
			if i.Name != inst.Name {
				continue
			}
			d := deps.Discoverer(i)
			guests, err := d.DiscoverGuests(ctx)
			if err != nil {
				fmt.Fprintf(deps.ErrOut, "Discovery failed: %v\n", err)
				return nil
			}
			// Shared with the discovery loop: only running guests are
			// stored, so the list cannot contain an unconnectable guest.
			stored, _, err := proxmox.StoreGuests(ctx, deps.Repo, i, guests)
			if err != nil {
				fmt.Fprintf(deps.ErrOut, "Storing guests: %v\n", err)
			}
			fmt.Fprintf(deps.Out, "Discovered %d guests, %d running.\n", len(guests), stored)
			break
		}
	}
	return nil
}

// probeSSHAccessBeforeAdd checks that the node is reachable over SSH before the
// instance is stored, so a mistake is reported against the command that made
// it rather than against the first guest somebody tries to reach.
//
// An unverifiable host key (no pinned fingerprint and no DNSSEC-validated
// SSHFP) is fatal and returned, because the instance cannot be used over SSH
// until the operator confirms and pins a fingerprint. Every other failure --
// notably the public key not being installed on the host yet -- is NOT fatal:
// the administrator installs the key by hand, and cannot do that before an
// instance exists to name the host. Those print the key and what to do with
// it and return nil, so the caller adds the instance anyway.
//
// The reachability check runs in `proxpass serve' (root), which holds the
// private key this session cannot read; deps.SSHKeys is the loopback-API
// channel to it. The fatal host-key case is preserved across that boundary: a
// *sshhostkey.ErrNoFingerprint is reconstructed on this side, so errors.As
// still recognizes it.
func probeSSHAccessBeforeAdd(
	ctx context.Context,
	deps *Deps,
	inst *models.ProxmoxInstance,
	instName string,
) error {
	err := deps.SSHKeys.CheckInstanceSSHAccess(ctx, inst)
	if err == nil {
		return nil
	}

	var noFP *sshhostkey.ErrNoFingerprint
	if errors.As(err, &noFP) {
		// The error already names the presented fingerprint and how to pin it.
		return err
	}

	pub, _, pubErr := deps.SSHKeys.SSHPublicKey(ctx)
	if pubErr != nil {
		return fmt.Errorf("deriving the public key: %w", pubErr)
	}
	fmt.Fprintf(deps.ErrOut,
		"Warning: %s is not reachable over SSH yet: %v\n"+
			"Add this key to %s on %s, then run `instance inspect %s' to re-check:\n%s",
		inst.SSHHost, err, authorizedKeysPath, inst.SSHHost, instName, pub)
	return nil
}

// checkTermProxyVersion creates a temporary APIClient and verifies that the
// Proxmox VE version supports termproxy with API token auth.
func checkTermProxyVersion(ctx context.Context, apiURL, tokenID, tokenSecret string) error {
	inst := &models.ProxmoxInstance{
		APIURL:         apiURL,
		APITokenID:     tokenID,
		APITokenSecret: tokenSecret,
	}
	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		return err
	}
	return client.CheckTermProxySupport(ctx)
}

// resolveInstanceNode creates a temporary APIClient and resolves the
// Proxmox node name that should be stored with this instance.
//
// When sshHost is non-empty it is matched against the cluster node list
// (exact or FQDN-prefix match). When sshHost is empty, or when it matches no
// node, the node that served the API request (--api-url points at exactly one
// node) is used. See proxmox.APIClient.ResolveNodeName.
func resolveInstanceNode(ctx context.Context, apiURL, tokenID, tokenSecret, sshHost string) (string, error) {
	inst := &models.ProxmoxInstance{
		APIURL:         apiURL,
		APITokenID:     tokenID,
		APITokenSecret: tokenSecret,
		SSHHost:        sshHost,
	}
	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		return "", err
	}
	return client.ResolveNodeName(ctx, sshHost)
}
