package testenv

import (
	"fmt"
	"os"
	"testing"

	"proxpass/internal/db"
)

// TestEnv bundles all mock infrastructure for integration testing.
type TestEnv struct {
	Repo   db.Repository
	API    *MockAPIServer
	SSH    *MockSSHServer
	Seed   *SeedData
	dbPath string
}

// New creates a complete test environment with mock servers and
// a seeded database. Call Close() when done.
func New(t *testing.T) *TestEnv {
	t.Helper()

	cfg := DefaultConfig()

	// Create temp DB
	f, err := os.CreateTemp("", "proxpass-test-*.db")
	if err != nil {
		t.Fatalf("testenv: temp db: %v", err)
	}
	_ = f.Close()
	dbPath := f.Name()

	repo, err := db.NewSQLiteRepository(dbPath)
	if err != nil {
		_ = os.Remove(dbPath)
		t.Fatalf("testenv: open db: %v", err)
	}

	// Start mock SSH server
	sshSrv, err := NewMockSSHServer()
	if err != nil {
		_ = repo.Close()
		_ = os.Remove(dbPath)
		t.Fatalf("testenv: mock ssh: %v", err)
	}

	// Start mock API server
	apiSrv := NewMockAPIServer(cfg.API.TokenID, cfg.API.TokenSecret)
	apiSrv.LoadFromConfig(cfg)

	// Seed the database
	seed, err := Seed(repo, apiSrv.URL(), sshSrv.Host, sshSrv.Port, sshSrv.KeyPath)
	if err != nil {
		apiSrv.Close()
		sshSrv.Close()
		_ = repo.Close()
		_ = os.Remove(dbPath)
		t.Fatalf("testenv: seed: %v", err)
	}

	env := &TestEnv{
		Repo:   repo,
		API:    apiSrv,
		SSH:    sshSrv,
		Seed:   seed,
		dbPath: dbPath,
	}

	t.Cleanup(func() { env.Close() })
	return env
}

// NewStandalone creates a test environment without a *testing.T,
// for use in standalone demo binaries. Returns an error instead
// of calling t.Fatal.
func NewStandalone() (*TestEnv, error) {
	cfg := DefaultConfig()

	f, err := os.CreateTemp("", "proxpass-demo-*.db")
	if err != nil {
		return nil, fmt.Errorf("temp db: %w", err)
	}
	_ = f.Close()
	dbPath := f.Name()

	repo, err := db.NewSQLiteRepository(dbPath)
	if err != nil {
		_ = os.Remove(dbPath)
		return nil, fmt.Errorf("open db: %w", err)
	}

	sshSrv, err := NewMockSSHServer()
	if err != nil {
		_ = repo.Close()
		_ = os.Remove(dbPath)
		return nil, fmt.Errorf("mock ssh: %w", err)
	}

	apiSrv := NewMockAPIServer(cfg.API.TokenID, cfg.API.TokenSecret)
	apiSrv.LoadFromConfig(cfg)

	seed, err := Seed(repo, apiSrv.URL(), sshSrv.Host, sshSrv.Port, sshSrv.KeyPath)
	if err != nil {
		apiSrv.Close()
		sshSrv.Close()
		_ = repo.Close()
		_ = os.Remove(dbPath)
		return nil, fmt.Errorf("seed: %w", err)
	}

	return &TestEnv{
		Repo:   repo,
		API:    apiSrv,
		SSH:    sshSrv,
		Seed:   seed,
		dbPath: dbPath,
	}, nil
}

// Close tears down all mock servers and removes temp files.
func (e *TestEnv) Close() {
	if e.API != nil {
		e.API.Close()
	}
	if e.SSH != nil {
		e.SSH.Close()
	}
	if e.Repo != nil {
		_ = e.Repo.Close()
	}
	if e.dbPath != "" {
		_ = os.Remove(e.dbPath)
	}
}
