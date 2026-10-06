// Command proxpass is the Proxmox SSH proxy.
//
// It no longer implements an SSH server. OpenSSH's sshd owns the protocol and
// invokes this binary in three roles:
//
//	proxpass serve            long-running: guest discovery + the NSS
//	                          directory API that sshd resolves users through
//	proxpass authorized-keys  sshd AuthorizedKeysCommand
//	proxpass session          sshd ForceCommand, i.e. the user's login shell
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ucli "github.com/urfave/cli/v3"

	"proxpass/internal/api"
	"proxpass/internal/cli"
	"proxpass/internal/console"
	"proxpass/internal/db"
	"proxpass/internal/proxmox"
	"proxpass/internal/session"
)

func main() {
	os.Exit(run())
}

func run() int {
	cmd := &ucli.Command{
		Name:  "proxpass",
		Usage: "Proxmox SSH proxy",
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name: "data",
				Usage: "SQLite file path, or a postgres:// URL " +
					"(e.g. postgres://user:pass@host/proxpass?sslmode=disable)",
				Value:   "/var/lib/proxpass/proxpass.db",
				Sources: ucli.EnvVars("PROXPASS_DATA"),
			},
			&ucli.StringFlag{
				Name:    "log-level",
				Usage:   "log level (debug, info, warn, error)",
				Value:   "info",
				Sources: ucli.EnvVars("PROXPASS_LOG_LEVEL"),
			},
			&ucli.StringFlag{
				Name:    "admin-key",
				Usage:   "admin SSH public key (authorized_keys format)",
				Sources: ucli.EnvVars("PROXPASS_ADMIN_KEY"),
			},
			&ucli.StringFlag{
				Name: "public-endpoint",
				Usage: "hostname clients use to reach this proxpass " +
					"(shown in the status bar)",
				Sources: ucli.EnvVars("PROXPASS_PUBLIC_ENDPOINT"),
			},
		},
		Commands: []*ucli.Command{
			serveCommand(),
			authorizedKeysCommand(),
			sessionCommand(),
		},
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := cmd.Run(ctx, os.Args); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func serveCommand() *ucli.Command {
	return &ucli.Command{
		Name:  "serve",
		Usage: "run guest discovery and the NSS directory API",
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name:    "listen",
				Usage:   "address for the NSS directory API",
				Value:   "127.0.0.1:8080",
				Sources: ucli.EnvVars("PROXPASS_LISTEN"),
			},
			&ucli.DurationFlag{
				Name:    "discovery-interval",
				Usage:   "guest discovery poll interval",
				Value:   5 * time.Minute,
				Sources: ucli.EnvVars("PROXPASS_DISCOVERY_INTERVAL"),
			},
		},
		Action: runServe,
	}
}

func runServe(ctx context.Context, cmd *ucli.Command) error {
	listenAddr := cmd.String("listen")
	dataPath := cmd.String("data")
	interval := cmd.Duration("discovery-interval")

	logger := log.New(os.Stdout, "proxpass: ", log.LstdFlags)
	logger.Printf("config: listen=%s data=%s discovery-interval=%s",
		listenAddr, dataPath, interval)

	// Resolve the uid/gid layout before anything else: an invalid one must
	// fail at startup rather than after sshd has accepted a key, where it
	// surfaces as "setresuid ...: Invalid argument".
	ids, err := api.LoadIDLayout(os.LookupEnv)
	if err != nil {
		return fmt.Errorf("id layout: %w", err)
	}
	logger.Printf("id layout: admin uid=%d gid=%d, client gid=%d, uid base=%d, gid base=%d, max=%d",
		ids.AdminUID, ids.AdminGroupGID, ids.SharedGroupGID,
		ids.UIDBase, ids.GIDBase, ids.MaxID)

	repo, err := db.NewRepository(dataPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = repo.Close() }()

	// Persist the admin key supplied via --admin-key/PROXPASS_ADMIN_KEY.
	//
	// sshd runs AuthorizedKeysCommand with a scrubbed environment, so that
	// process cannot see PROXPASS_ADMIN_KEY. Storing the key here is what
	// makes it visible to the key lookup; otherwise the admin can never log
	// in and sshd just reports "Failed publickey".
	if err := storeAdminKey(ctx, repo, cmd.String("admin-key"), logger); err != nil {
		return err
	}

	// Same reason as the admin key: a session cannot see this in its
	// environment, so serve writes it down where the session can read it.
	if err := storePublicEndpoint(ctx, repo, cmd.String("public-endpoint"), logger); err != nil {
		return err
	}

	// Guest discovery runs in the background; the directory API blocks.
	discovery := proxmox.NewDiscovery(
		repo, interval, logger, proxmox.DefaultDiscovererFactory)
	go discovery.Run(ctx)

	logger.Printf("serving directory API on %s", listenAddr)
	if err := api.NewServerWithIDs(repo, logger, ids).ListenAndServe(ctx, listenAddr); err != nil {
		return err
	}
	logger.Println("shutting down")
	return nil
}

// storeAdminKey records the startup admin key in the database if it is not
// already present, so that later "authorized-keys" invocations can find it.
func storeAdminKey(ctx context.Context, repo db.Repository, rawKey string, logger *log.Logger) error {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil
	}
	// Reject a malformed key at startup rather than silently never
	// authorizing anybody. The validation is strict about being a single
	// entry: a multi-line value here would install several admin
	// credentials, only one of which anybody reviewed.
	rawKey, err := cli.ValidatePublicKey(rawKey)
	if err != nil {
		return fmt.Errorf("invalid --admin-key: %w", err)
	}

	existing, err := repo.ListAdminKeys(ctx)
	if err != nil {
		return fmt.Errorf("listing admin keys: %w", err)
	}
	for _, k := range existing {
		if strings.TrimSpace(k) == rawKey {
			return nil
		}
	}
	if err := repo.AddAdminKey(ctx, rawKey); err != nil {
		return fmt.Errorf("storing admin key: %w", err)
	}
	logger.Println("admin key from configuration stored")
	return nil
}

// storePublicEndpoint records the hostname clients use to reach this proxpass,
// so that a session can show it in the status bar.
//
// A session cannot read this from its environment: sshd builds a fresh one and
// does not inherit the container's, so the value reaches `proxpass serve' and
// nothing else. It is written to the database for the same reason the admin
// key is, and read back from there.
//
// Unlike the admin key it is updated rather than added, because it describes
// the deployment rather than granting anything: changing the compose file and
// restarting should change what sessions display. Clearing it removes the
// stored value, so the status bar stops showing an endpoint that is no longer
// right instead of keeping a stale one forever.
func storePublicEndpoint(ctx context.Context, repo db.Repository, endpoint string, logger *log.Logger) error {
	endpoint = strings.TrimSpace(endpoint)

	current, err := repo.GetSetting(ctx, db.SettingPublicEndpoint)
	if err != nil {
		return fmt.Errorf("reading public endpoint: %w", err)
	}
	if current == endpoint {
		return nil
	}
	if err := repo.SetSetting(ctx, db.SettingPublicEndpoint, endpoint); err != nil {
		return fmt.Errorf("storing public endpoint: %w", err)
	}
	if endpoint == "" {
		logger.Println("public endpoint cleared")
		return nil
	}
	logger.Printf("public endpoint set to %q", endpoint)
	return nil
}

func authorizedKeysCommand() *ucli.Command {
	return &ucli.Command{
		Name:      "authorized-keys",
		Usage:     "print authorized_keys lines for a user (sshd AuthorizedKeysCommand)",
		ArgsUsage: "<username>",
		Action:    runAuthorizedKeys,
	}
}

func runAuthorizedKeys(ctx context.Context, cmd *ucli.Command) error {
	user := cmd.Args().First()
	if user == "" {
		// sshd should always pass a user, but never fail loudly here: any
		// stdout noise would be parsed as a key.
		return nil
	}

	repo, err := db.NewRepository(cmd.String("data"))
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = repo.Close() }()

	return session.WriteAuthorizedKeys(
		ctx, os.Stdout, repo, user, cmd.String("admin-key"))
}

func sessionCommand() *ucli.Command {
	return &ucli.Command{
		Name:  "session",
		Usage: "run a client session (sshd ForceCommand)",
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name:    "user",
				Usage:   "login name; defaults to $USER",
				Sources: ucli.EnvVars("USER"),
			},
			&ucli.StringFlag{
				Name:    "command",
				Usage:   "requested command; defaults to $SSH_ORIGINAL_COMMAND",
				Sources: ucli.EnvVars("SSH_ORIGINAL_COMMAND"),
			},
		},
		Action: runSession,
	}
}

func runSession(ctx context.Context, cmd *ucli.Command) error {
	user := cmd.String("user")
	if user == "" {
		return fmt.Errorf("no user; sshd should set $USER")
	}

	repo, err := db.NewRepository(cmd.String("data"))
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = repo.Close() }()

	// The key, not the login name, says who this is. The name is an alias
	// the caller chose -- the directory serves any unused one so sshd can
	// reach the key check at all -- so it cannot be trusted to identify
	// anybody. See ResolveIdentityByKey.
	identity, err := session.ResolveIdentityByKey(
		ctx, repo, user, session.AuthInfoPath(), cmd.String("admin-key"))
	if err != nil {
		return err
	}

	term, restore := currentTerminal()
	defer restore()

	// Sessions log to stderr, which on an interactive login is the user's
	// terminal: stdout carries the guest console. The log writer therefore
	// has to go through UIErr as well, or raw mode turns each log line's
	// newline into a bare LF and the messages staircase across whatever the
	// session is drawing.
	logger := log.New(term.UIErr(), "proxpass: ", log.LstdFlags)

	// The endpoint comes from the database, not the flag: sshd gives this
	// process a fresh environment, so PROXPASS_PUBLIC_ENDPOINT is never set
	// here. `proxpass serve' recorded it for exactly this reason. A failure
	// to read it must not cost the user their session -- the endpoint is
	// cosmetic -- so it degrades to the shorter label.
	publicEndpoint, err := repo.GetSetting(ctx, db.SettingPublicEndpoint)
	if err != nil {
		logger.Printf("reading the public endpoint: %v", err)
		publicEndpoint = ""
	}

	code := session.Run(ctx, &session.Deps{
		Repo:        repo,
		Discoverer:  proxmox.DefaultDiscovererFactory,
		Proxier:     console.DefaultProxier{PublicEndpoint: publicEndpoint},
		Logger:      logger,
		Terminal:    term,
		User:        identity.User,
		DisplayName: identity.DisplayName,
		IsAdmin:     identity.IsAdmin,
		ClientID:    identity.ClientID,
		Command:     cmd.String("command"),
	})
	// The session already reported any problem to the user, so surface the
	// status without printing a second, redundant error. Restore the
	// terminal explicitly first: ucli.Exit unwinds through os.Exit, which
	// would skip the deferred restore.
	if code != 0 {
		restore()
		return ucli.Exit("", code)
	}
	return nil
}
