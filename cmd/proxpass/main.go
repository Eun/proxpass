package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

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
