// proxmox-mock starts a mock Proxmox API and SSH server for testing.
//
// Usage:
//
//	proxmox-mock --config mock-config.yaml
//	proxmox-mock  # uses built-in defaults
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	cli "github.com/urfave/cli/v3"

	"proxpass/internal/testenv"
)

func main() {
	os.Exit(run0())
}

func run0() int {
	cmd := &cli.Command{
		Name:  "proxmox-mock",
		Usage: "Mock Proxmox API and SSH server for testing",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "path to YAML config file",
				Sources: cli.EnvVars("PROXMOX_MOCK_CONFIG"),
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

func run(_ context.Context, cmd *cli.Command) error {
	logger := log.New(os.Stdout, "proxmox-mock: ", log.LstdFlags)

	configPath := cmd.String("config")

	var cfg *testenv.MockConfig
	if configPath != "" {
		var err error
		cfg, err = testenv.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		logger.Printf("loaded config from %s", configPath)
	} else {
		cfg = testenv.DefaultConfig()
		logger.Println("using built-in default config")
	}

	// Start mock API server.
	apiSrv := testenv.NewMockAPIServerStandalone(
		cfg.API.TokenID, cfg.API.TokenSecret)
	apiSrv.LoadFromConfig(cfg)

	go func() {
		if err := apiSrv.ListenAndServe(
			cfg.API.ListenAddr,
		); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("api server: %v", err)
		}
	}()

	// Start mock SSH server.
	sshSrv, err := testenv.NewMockSSHServerOnAddr(
		cfg.SSH.ListenAddr, cfg.SSH.KeyPath)
	if err != nil {
		return fmt.Errorf("mock ssh: %w", err)
	}

	fmt.Println("=========================================")
	fmt.Println("  Mock Proxmox Service")
	fmt.Printf("  API: http://127.0.0.1%s\n",
		cfg.API.ListenAddr)
	fmt.Printf("  SSH: 127.0.0.1%s\n",
		cfg.SSH.ListenAddr)
	fmt.Printf("  SSH key: %s\n", sshSrv.KeyPath)
	fmt.Printf("  API Token ID:     %s\n",
		cfg.API.TokenID)
	fmt.Printf("  API Token Secret: %s\n",
		cfg.API.TokenSecret)
	fmt.Println()
	fmt.Println("  Nodes and guests:")
	for _, n := range cfg.Nodes {
		fmt.Printf("    %s:\n", n.Name)
		for _, g := range n.Guests {
			fmt.Printf("      %s %d %s (%s)\n",
				g.Type, g.VMID, g.Name, g.Status)
		}
	}
	fmt.Println()
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println("=========================================")

	// Block until signal.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	apiSrv.Close()
	sshSrv.Close()
	logger.Println("shutting down")
	return nil
}
