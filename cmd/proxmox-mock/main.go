package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"proxpass/internal/testenv"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file (uses defaults if omitted)")
	flag.Parse()

	logger := log.New(os.Stdout, "proxmox-mock: ", log.LstdFlags)

	var cfg *testenv.MockConfig
	if *configPath != "" {
		var err error
		cfg, err = testenv.LoadConfig(*configPath)
		if err != nil {
			logger.Fatalf("load config: %v", err)
		}
	} else {
		cfg = testenv.DefaultConfig()
	}

	// Start mock API server (standalone mode — fixed port, plain HTTP)
	apiSrv := testenv.NewMockAPIServerStandalone(cfg.API.TokenID, cfg.API.TokenSecret)
	apiSrv.LoadFromConfig(cfg)

	// Start the API listener in the background
	go func() {
		if err := apiSrv.ListenAndServe(cfg.API.ListenAddr); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("api server: %v", err)
		}
	}()

	// Start mock SSH server on the configured address
	sshSrv, err := testenv.NewMockSSHServerOnAddr(cfg.SSH.ListenAddr)
	if err != nil {
		logger.Fatalf("mock ssh: %v", err)
	}

	fmt.Println("=========================================")
	fmt.Println("  Mock Proxmox Service")
	fmt.Printf("  API: http://127.0.0.1%s\n", cfg.API.ListenAddr)
	fmt.Printf("  SSH: 127.0.0.1%s\n", cfg.SSH.ListenAddr)
	fmt.Printf("  SSH key: %s\n", sshSrv.KeyPath)
	fmt.Printf("  API Token ID:     %s\n", cfg.API.TokenID)
	fmt.Printf("  API Token Secret: %s\n", cfg.API.TokenSecret)
	fmt.Println()
	fmt.Println("  Nodes and guests:")
	for _, n := range cfg.Nodes {
		fmt.Printf("    %s:\n", n.Name)
		for _, g := range n.Guests {
			fmt.Printf("      %s %d %s (%s)\n", g.Type, g.VMID, g.Name, g.Status)
		}
	}
	fmt.Println()
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println("=========================================")

	// Block until signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	apiSrv.Close()
	sshSrv.Close()
	logger.Println("shutting down")
}
