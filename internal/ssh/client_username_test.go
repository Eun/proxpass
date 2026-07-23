package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	proxssh "proxpass/internal/ssh"
	"proxpass/internal/testenv"

	gossh "golang.org/x/crypto/ssh"
)

// setupClientTest starts a proxpass Server backed by testenv, replaces alice's
// public key with a freshly generated one, and returns the server address,
// client signer, mock proxier, and a cancel func.
//
// Access seeded by testenv.Seed:
//   - alice -> webserver (ct100)  [direct]
//   - alice (via developers group) -> devbox (vm200)  [group]
func setupClientTest(t *testing.T) (
	addr string,
	clientSigner gossh.Signer,
	mp *testenv.MockProxier,
	cancel context.CancelFunc,
) {
	t.Helper()

	env := testenv.New(t)

	// Generate a fresh client keypair so we control the private key.
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientSSHPub, err := gossh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatalf("client ssh pub: %v", err)
	}
	pemBlock, err := gossh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	clientSigner, err = gossh.ParsePrivateKey(pem.EncodeToMemory(pemBlock))
	if err != nil {
		t.Fatalf("parse client signer: %v", err)
	}

	// Replace alice's key in the DB with our freshly generated key.
	authorizedLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(clientSSHPub)))
	ctx := context.Background()

	client := env.Seed.Client
	client.PublicKeys = []string{authorizedLine}
	if err := env.Repo.UpdateClient(ctx, client); err != nil {
		t.Fatalf("update client key: %v", err)
	}

	hostKeyPath := t.TempDir() + "/host.key"

	logger := log.New(io.Discard, "", 0)
	mp = &testenv.MockProxier{}

	adminHandler := proxssh.DefaultAdminHandler(mp, nil, logger)

	srv := proxssh.NewServer(
		"127.0.0.1:0",
		hostKeyPath,
		env.Repo,
		adminHandler,
		mp,
		logger,
	)

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr = ln.Addr().String()

	ctx2, cancelCtx := context.WithCancel(context.Background())
	cancel = cancelCtx

	go func() {
		_ = srv.ListenAndServeOn(ctx2, ln)
	}()

	if err := waitForSSH(addr, 5*time.Second); err != nil {
		t.Fatalf("proxpass server not ready: %v", err)
	}

	return addr, clientSigner, mp, cancel
}
