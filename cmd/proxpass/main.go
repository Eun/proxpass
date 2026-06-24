package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	gossh "golang.org/x/crypto/ssh"

	"proxpass/internal/db"
	"proxpass/internal/proxmox"
	proxssh "proxpass/internal/ssh"
	"proxpass/internal/tui"
)

func envOrDefault(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func main() {
	listenAddr := flag.String("listen", envOrDefault("PROXPASS_LISTEN", ":2222"), "SSH listen address")
	hostKeyPath := flag.String("host-key", envOrDefault("PROXPASS_HOST_KEY", "./proxpass_host_key"), "path to SSH host key")
	dataPath := flag.String("data", envOrDefault("PROXPASS_DATA", "./proxpass.db"), "path to SQLite database")
	discoveryIntervalStr := flag.String("discovery-interval",
		envOrDefault("PROXPASS_DISCOVERY_INTERVAL", "5m"),
		"discovery poll interval")
	logLevel := flag.String("log-level", envOrDefault("PROXPASS_LOG_LEVEL", "info"), "log level (debug, info, warn, error)")
	adminUser := flag.String("admin-user",
		envOrDefault("PROXPASS_ADMIN_USER", ""),
		"bootstrap admin SSH username")
	adminKey := flag.String("admin-key",
		envOrDefault("PROXPASS_ADMIN_KEY", ""),
		"bootstrap admin SSH public key (authorized_key format)")
	flag.Parse()

	discoveryInterval, err := time.ParseDuration(*discoveryIntervalStr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr,
			"invalid discovery interval %q: %v\n",
			*discoveryIntervalStr, err)
		os.Exit(1)
	}

	logger := log.New(os.Stdout, "proxpass: ", log.LstdFlags)
	logger.Printf(
		"config: listen=%s host-key=%s data=%s "+
			"discovery-interval=%s log-level=%s",
		*listenAddr, *hostKeyPath, *dataPath,
		discoveryInterval, *logLevel)

	// Open database.
	repo, err := db.NewSQLiteRepository(*dataPath)
	if err != nil {
		logger.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = repo.Close() }()

	// Wire up the TUI factory so the SSH admin handler can create TUI models.
	proxssh.SetTUIFactory(func(r db.Repository) tea.Model {
		return tui.NewModel(r)
	})

	// Create services.
	adminHandler := proxssh.DefaultAdminHandler(tui.RunTUI, logger)
	discovery := proxmox.NewDiscovery(repo, discoveryInterval, logger)
	server := proxssh.NewServer(
		*listenAddr, *hostKeyPath, repo, adminHandler, logger)

	// Bootstrap admin: if both --admin-user and --admin-key are set,
	// configure the server to accept that credential as an admin
	// before consulting the database.
	if err := configureBootstrapAdmin(
		server, *adminUser, *adminKey, logger,
	); err != nil {
		logger.Fatalf("bootstrap admin: %v", err)
	}

	// Context canceled on SIGINT / SIGTERM.
	ctx, cancel := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Run discovery in the background.
	go discovery.Run(ctx)

	// Run SSH server (blocks until ctx is canceled or fatal error).
	logger.Printf("starting SSH server on %s", *listenAddr)
	if err := server.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
		logger.Fatalf("ssh server error: %v", err)
	}

	logger.Println("shutting down")
}

// configureBootstrapAdmin parses and sets the bootstrap admin on the
// server if both username and key are provided.
func configureBootstrapAdmin(
	server *proxssh.Server,
	username, rawKey string,
	logger *log.Logger,
) error {
	username = strings.TrimSpace(username)
	rawKey = strings.TrimSpace(rawKey)

	// Both must be set, or neither.
	if username == "" && rawKey == "" {
		return nil
	}
	if username == "" || rawKey == "" {
		return fmt.Errorf(
			"--admin-user and --admin-key must both be set")
	}

	pub, err := parsePublicKey(rawKey)
	if err != nil {
		return fmt.Errorf("invalid SSH public key: %w", err)
	}

	server.SetBootstrapAdmin(username, pub)
	logger.Printf(
		"bootstrap admin configured: user=%q", username)
	return nil
}

// parsePublicKey extracts the public key from an authorized_key line.
func parsePublicKey(raw string) (gossh.PublicKey, error) {
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(raw)) //nolint:dogsled // SSH parsing returns 5 values
	return pub, err
}
