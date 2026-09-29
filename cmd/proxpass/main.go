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

	cli "github.com/urfave/cli/v3"
	gossh "golang.org/x/crypto/ssh"

	"proxpass/internal/api"
	"proxpass/internal/console"
	"proxpass/internal/db"
	"proxpass/internal/proxmox"
	"proxpass/internal/session"
)

func main() {
	os.Exit(run())
}

func run() int {
	cmd := &cli.Command{
		Name:  "proxpass",
		Usage: "Proxmox SSH proxy",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "data",
				Usage:   "path to SQLite database",
				Value:   "/var/lib/proxpass/proxpass.db",
				Sources: cli.EnvVars("PROXPASS_DATA"),
			},
			&cli.StringFlag{
				Name:    "log-level",
				Usage:   "log level (debug, info, warn, error)",
				Value:   "info",
				Sources: cli.EnvVars("PROXPASS_LOG_LEVEL"),
			},
			&cli.StringFlag{
				Name:    "admin-key",
				Usage:   "admin SSH public key (authorized_keys format)",
				Sources: cli.EnvVars("PROXPASS_ADMIN_KEY"),
			},
		},
		Commands: []*cli.Command{
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

func serveCommand() *cli.Command {
	return &cli.Command{
		Name:  "serve",
		Usage: "run guest discovery and the NSS directory API",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "listen",
				Usage:   "address for the NSS directory API",
				Value:   "127.0.0.1:8080",
				Sources: cli.EnvVars("PROXPASS_LISTEN"),
			},
			&cli.DurationFlag{
				Name:    "discovery-interval",
				Usage:   "guest discovery poll interval",
				Value:   5 * time.Minute,
				Sources: cli.EnvVars("PROXPASS_DISCOVERY_INTERVAL"),
			},
		},
		Action: runServe,
	}
}

func runServe(ctx context.Context, cmd *cli.Command) error {
	listenAddr := cmd.String("listen")
	dataPath := cmd.String("data")
	interval := cmd.Duration("discovery-interval")

	logger := log.New(os.Stdout, "proxpass: ", log.LstdFlags)
	logger.Printf("config: listen=%s data=%s discovery-interval=%s",
		listenAddr, dataPath, interval)

	repo, err := db.NewSQLiteRepository(dataPath)
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

	// Guest discovery runs in the background; the directory API blocks.
	discovery := proxmox.NewDiscovery(
		repo, interval, logger, proxmox.DefaultDiscovererFactory)
	go discovery.Run(ctx)

	logger.Printf("serving directory API on %s", listenAddr)
	if err := api.NewServer(repo, logger).ListenAndServe(ctx, listenAddr); err != nil {
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
	// authorizing anybody.
	if _, _, _, _, err := gossh.ParseAuthorizedKey([]byte(rawKey)); err != nil {
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

func authorizedKeysCommand() *cli.Command {
	return &cli.Command{
		Name:      "authorized-keys",
		Usage:     "print authorized_keys lines for a user (sshd AuthorizedKeysCommand)",
		ArgsUsage: "<username>",
		Action:    runAuthorizedKeys,
	}
}

func runAuthorizedKeys(ctx context.Context, cmd *cli.Command) error {
	user := cmd.Args().First()
	if user == "" {
		// sshd should always pass a user, but never fail loudly here: any
		// stdout noise would be parsed as a key.
		return nil
	}

	repo, err := db.NewSQLiteRepository(cmd.String("data"))
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = repo.Close() }()

	return session.WriteAuthorizedKeys(
		ctx, os.Stdout, repo, user, cmd.String("admin-key"))
}

func sessionCommand() *cli.Command {
	return &cli.Command{
		Name:  "session",
		Usage: "run a client session (sshd ForceCommand)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "user",
				Usage:   "login name; defaults to $USER",
				Sources: cli.EnvVars("USER"),
			},
			&cli.StringFlag{
				Name:    "command",
				Usage:   "requested command; defaults to $SSH_ORIGINAL_COMMAND",
				Sources: cli.EnvVars("SSH_ORIGINAL_COMMAND"),
			},
		},
		Action: runSession,
	}
}

func runSession(ctx context.Context, cmd *cli.Command) error {
	// Sessions log to stderr: stdout is the user's terminal stream.
	logger := log.New(os.Stderr, "proxpass: ", log.LstdFlags)

	user := cmd.String("user")
	if user == "" {
		return fmt.Errorf("no user; sshd should set $USER")
	}

	repo, err := db.NewSQLiteRepository(cmd.String("data"))
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = repo.Close() }()

	identity, err := session.ResolveIdentity(ctx, repo, user)
	if err != nil {
		return err
	}

	term, restore := currentTerminal()
	defer restore()

	code := session.Run(ctx, &session.Deps{
		Repo:       repo,
		Discoverer: proxmox.DefaultDiscovererFactory,
		Proxier:    console.DefaultProxier{},
		Logger:     logger,
		Terminal:   term,
		User:       identity.User,
		IsAdmin:    identity.IsAdmin,
		ClientID:   identity.ClientID,
		Command:    cmd.String("command"),
	})
	// The session already reported any problem to the user, so surface the
	// status without printing a second, redundant error. Restore the
	// terminal explicitly first: cli.Exit unwinds through os.Exit, which
	// would skip the deferred restore.
	if code != 0 {
		restore()
		return cli.Exit("", code)
	}
	return nil
}
