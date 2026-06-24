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

	tea "github.com/charmbracelet/bubbletea"
	cli "github.com/urfave/cli/v3"
	gossh "golang.org/x/crypto/ssh"

	"proxpass/internal/db"
	"proxpass/internal/proxmox"
	proxssh "proxpass/internal/ssh"
	"proxpass/internal/tui"
)

func main() {
	os.Exit(run0())
}

func run0() int {
	cmd := &cli.Command{
		Name:  "proxpass",
		Usage: "Proxmox SSH proxy with admin TUI",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "listen",
				Usage:   "SSH listen address",
				Value:   ":2222",
				Sources: cli.EnvVars("PROXPASS_LISTEN"),
			},
			&cli.StringFlag{
				Name:    "host-key",
				Usage:   "path to SSH host key",
				Value:   "./proxpass_host_key",
				Sources: cli.EnvVars("PROXPASS_HOST_KEY"),
			},
			&cli.StringFlag{
				Name:    "data",
				Usage:   "path to SQLite database",
				Value:   "./proxpass.db",
				Sources: cli.EnvVars("PROXPASS_DATA"),
			},
			&cli.DurationFlag{
				Name:    "discovery-interval",
				Usage:   "discovery poll interval",
				Value:   5 * time.Minute,
				Sources: cli.EnvVars("PROXPASS_DISCOVERY_INTERVAL"),
			},
			&cli.StringFlag{
				Name:    "log-level",
				Usage:   "log level (debug, info, warn, error)",
				Value:   "info",
				Sources: cli.EnvVars("PROXPASS_LOG_LEVEL"),
			},
			&cli.StringFlag{
				Name:  "admin-key",
				Usage: "flag-based admin SSH public key (authorized_key format)",
				Sources: cli.EnvVars(
					"PROXPASS_ADMIN_KEY"),
			},
		},
		Action: run,
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

func run(ctx context.Context, cmd *cli.Command) error {
	listenAddr := cmd.String("listen")
	hostKeyPath := cmd.String("host-key")
	dataPath := cmd.String("data")
	discoveryInterval := cmd.Duration("discovery-interval")
	logLevel := cmd.String("log-level")
	adminKey := cmd.String("admin-key")

	logger := log.New(os.Stdout, "proxpass: ", log.LstdFlags)
	logger.Printf(
		"config: listen=%s host-key=%s data=%s "+
			"discovery-interval=%s log-level=%s",
		listenAddr, hostKeyPath, dataPath,
		discoveryInterval, logLevel)

	// Open database.
	repo, err := db.NewSQLiteRepository(dataPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = repo.Close() }()

	// Wire up the TUI factory so the SSH admin handler can
	// create TUI models.
	proxssh.SetTUIFactory(func(r db.Repository) tea.Model {
		return tui.NewModel(r)
	})

	// Create services.
	adminHandler := proxssh.DefaultAdminHandler(
		tui.RunTUI, logger)
	discovery := proxmox.NewDiscovery(
		repo, discoveryInterval, logger)
	server := proxssh.NewServer(
		listenAddr, hostKeyPath, repo, adminHandler, logger)

	// Flag-based admin: if both --admin-user and --admin-key
	// are set, the server accepts that credential as an admin
	// for the lifetime of the process, checked before any
	// database lookup.
	if err := configureFlagAdmin(
		server, adminKey, logger,
	); err != nil {
		return fmt.Errorf("flag admin: %w", err)
	}

	// Run discovery in the background.
	go discovery.Run(ctx)

	// Run SSH server (blocks until ctx is canceled or fatal
	// error).
	logger.Printf("starting SSH server on %s", listenAddr)
	if err := server.ListenAndServe(ctx); err != nil &&
		ctx.Err() == nil {
		return fmt.Errorf("ssh server error: %w", err)
	}

	logger.Println("shutting down")
	return nil
}

// configureFlagAdmin parses and sets the flag-based admin key
// on the server. The credential stays active for the lifetime
// of the process.
func configureFlagAdmin(
	server *proxssh.Server,
	rawKey string,
	logger *log.Logger,
) error {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil
	}

	pub, err := parsePublicKey(rawKey)
	if err != nil {
		return fmt.Errorf("invalid SSH public key: %w", err)
	}

	server.SetFlagAdmin(pub)
	logger.Println("flag-based admin key configured")
	return nil
}

// parsePublicKey extracts the public key from an
// authorized_key line.
func parsePublicKey(raw string) (gossh.PublicKey, error) {
	//nolint:dogsled // SSH parsing returns 5 values
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(raw))
	return pub, err
}
