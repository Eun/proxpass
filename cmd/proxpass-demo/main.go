// proxpass-demo starts proxpass with mock Proxmox API and SSH servers
// so you can explore the application without a real Proxmox instance.
//
// Usage:
//
//	go run ./cmd/proxpass-demo
//	ssh -o StrictHostKeyChecking=no -p 2222 admin@127.0.0.1
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	gossh "golang.org/x/crypto/ssh"

	"proxpass/internal/db"
	"proxpass/internal/proxmox"
	proxssh "proxpass/internal/ssh"
	"proxpass/internal/testenv"
	"proxpass/internal/tui"
)

func main() {
	os.Exit(run())
}

func run() int {
	logger := log.New(os.Stdout, "demo: ", log.LstdFlags)

	// ---- stand up the mock environment ----
	env, err := testenv.NewStandalone()
	if err != nil {
		logger.Fatalf("testenv: %v", err)
	}
	defer env.Close()

	logger.Printf("mock Proxmox API running at %s", env.API.URL())
	logger.Printf("mock Proxmox SSH running at %s:%d",
		env.SSH.Host, env.SSH.Port)

	// ---- generate a temporary admin keypair ----
	adminPub, adminKeyPath, err := generateTempKey()
	if err != nil {
		logger.Fatalf("generate admin key: %v", err)
	}
	defer func() { _ = os.Remove(adminKeyPath) }()

	logger.Printf("admin private key written to %s", adminKeyPath)

	// ---- wire up proxpass using the mock repo ----
	proxssh.SetTUIFactory(func(r db.Repository) tea.Model {
		return tui.NewModel(r)
	})

	listenAddr := ":2222"
	hostKeyPath := filepath.Join(os.TempDir(), "proxpass-demo-hostkey")
	defer func() { _ = os.Remove(hostKeyPath) }()

	mockProxier := &testenv.MockProxier{}
	adminHandler := proxssh.DefaultAdminHandler(
		tui.RunTUI, mockProxier, logger)
	server := proxssh.NewServer(
		listenAddr, hostKeyPath, env.Repo,
		adminHandler, mockProxier, logger)

	// Set the admin key so we can SSH in.
	server.SetFlagAdmin(adminPub)

	// Run a single discovery pass so guests appear in the TUI.
	discovery := proxmox.NewDiscovery(
		env.Repo, 5*time.Minute, logger,
		proxmox.DefaultDiscovererFactory)
	if err := discovery.RunOnce(context.Background()); err != nil {
		logger.Printf("initial discovery: %v", err)
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Println()
	fmt.Println("=========================================")
	fmt.Println("  proxpass demo is running on :2222")
	fmt.Println()
	fmt.Println("  Connect with:")
	fmt.Printf(
		"    ssh -o StrictHostKeyChecking=no -i %s -p 2222 admin@127.0.0.1\n",
		adminKeyPath)
	fmt.Println()
	fmt.Println("  Pre-seeded data:")
	fmt.Println("    Instance: test-pve")
	fmt.Println("    Guests:   webserver (CT), database (CT),")
	fmt.Println("              devbox (VM), staging (VM)")
	fmt.Println("    Client:   alice")
	fmt.Println("    Group:    developers (alice)")
	fmt.Println("    Access:   alice → webserver (direct)")
	fmt.Println("              developers → devbox (group)")
	fmt.Println()
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println("=========================================")
	fmt.Println()

	if err := server.ListenAndServe(ctx); err != nil &&
		ctx.Err() == nil {
		logger.Fatalf("ssh server: %v", err)
	}

	logger.Println("shutting down")
	return 0
}

// generateTempKey creates an ED25519 keypair, writes the private key
// to a temp file, and returns the parsed public key + path.
func generateTempKey() (gossh.PublicKey, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate key: %w", err)
	}

	pemBlock, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, "", fmt.Errorf("marshal key: %w", err)
	}

	f, err := os.CreateTemp("", "proxpass-demo-admin-*")
	if err != nil {
		return nil, "", fmt.Errorf("temp file: %w", err)
	}
	if err := pem.Encode(f, pemBlock); err != nil {
		_ = f.Close()
		return nil, "", fmt.Errorf("write key: %w", err)
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, "", fmt.Errorf("chmod key: %w", err)
	}
	_ = f.Close()

	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		return nil, "", fmt.Errorf("ssh public key: %w", err)
	}

	return sshPub, f.Name(), nil
}
