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
	discoveryIntervalStr := flag.String("discovery-interval", envOrDefault("PROXPASS_DISCOVERY_INTERVAL", "5m"), "discovery poll interval")
	logLevel := flag.String("log-level", envOrDefault("PROXPASS_LOG_LEVEL", "info"), "log level (debug, info, warn, error)")
	adminKey := flag.String("admin-key",
		envOrDefault("PROXPASS_ADMIN_KEY", ""),
		"bootstrap admin public key (added if no admin keys exist)")
	flag.Parse()

	discoveryInterval, err := time.ParseDuration(*discoveryIntervalStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid discovery interval %q: %v\n", *discoveryIntervalStr, err)
		os.Exit(1)
	}

	logger := log.New(os.Stdout, "proxpass: ", log.LstdFlags)
	logger.Printf("config: listen=%s host-key=%s data=%s discovery-interval=%s log-level=%s",
		*listenAddr, *hostKeyPath, *dataPath, discoveryInterval, *logLevel)

	// Open database.
	repo, err := db.NewSQLiteRepository(*dataPath)
	if err != nil {
		logger.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = repo.Close() }()

	// Bootstrap: seed an admin key if the database has none.
	if *adminKey != "" {
		if err := seedAdminKey(repo, *adminKey, logger); err != nil {
			logger.Fatalf("failed to seed admin key: %v", err)
		}
	} else {
		keys, err := repo.ListAdminKeys(context.Background())
		if err != nil {
			logger.Fatalf("failed to list admin keys: %v", err)
		}
		if len(keys) == 0 {
			logger.Println("WARNING: no admin keys configured. Use --admin-key or PROXPASS_ADMIN_KEY to bootstrap.")
		}
	}

	// Wire up the TUI factory so the SSH admin handler can create TUI models.
	proxssh.SetTUIFactory(func(r db.Repository) tea.Model {
		return tui.NewModel(r)
	})

	// Create services.
	adminHandler := proxssh.DefaultAdminHandler(tui.RunTUI, logger)
	discovery := proxmox.NewDiscovery(repo, discoveryInterval, logger)
	server := proxssh.NewServer(*listenAddr, *hostKeyPath, repo, adminHandler, logger)

	// Context canceled on SIGINT / SIGTERM.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Run discovery in the background.
	go discovery.Run(ctx)

	// Run SSH server (blocks until ctx is canceled or a fatal error occurs).
	logger.Printf("starting SSH server on %s", *listenAddr)
	if err := server.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
		logger.Fatalf("ssh server error: %v", err)
	}

	logger.Println("shutting down")
}

// seedAdminKey validates and inserts an admin public key if not already present.
func seedAdminKey(repo db.Repository, raw string, logger *log.Logger) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("admin key is empty")
	}

	// Validate that it parses as an SSH public key.
	if _, _, _, _, err := gossh.ParseAuthorizedKey([]byte(raw)); err != nil {
		return fmt.Errorf("invalid SSH public key: %w", err)
	}

	existing, err := repo.ListAdminKeys(context.Background())
	if err != nil {
		return err
	}

	for _, k := range existing {
		if strings.TrimSpace(k) == raw {
			logger.Println("admin key already present, skipping seed")
			return nil
		}
	}

	if err := repo.AddAdminKey(context.Background(), raw); err != nil {
		return err
	}

	logger.Println("bootstrap: admin key added successfully")
	return nil
}
