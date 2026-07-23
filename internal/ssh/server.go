package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"proxpass/internal/db"

	gossh "golang.org/x/crypto/ssh"
)

const (
	roleAdmin  = "admin"
	roleClient = "client"
	permRole   = "role"
)

// Server is the proxpass SSH server.
type Server struct {
	listenAddr   string
	hostKeyPath  string
	repo         db.Repository
	adminHandler AdminSessionHandler
	proxier      GuestProxier
	logger       *log.Logger
	flagAdminKey gossh.PublicKey
}

// NewServer creates a new SSH server.
func NewServer(
	listenAddr, hostKeyPath string,
	repo db.Repository,
	adminHandler AdminSessionHandler,
	proxier GuestProxier,
	logger *log.Logger,
) *Server {
	return &Server{
		listenAddr:   listenAddr,
		hostKeyPath:  hostKeyPath,
		repo:         repo,
		adminHandler: adminHandler,
		proxier:      proxier,
		logger:       logger,
	}
}

// Proxier returns the server's GuestProxier.
func (s *Server) Proxier() GuestProxier {
	return s.proxier
}

// SetFlagAdmin configures a flag-based admin public key that is
// checked during authentication before any database lookup. The
// credential remains active for the lifetime of the process as
// long as the --admin-key flag (or PROXPASS_ADMIN_KEY env var)
// is present.
func (s *Server) SetFlagAdmin(key gossh.PublicKey) {
	s.flagAdminKey = key
}

// ListenAndServeOn starts the SSH server on the already-bound listener ln
// and blocks until ctx is canceled. The caller is responsible for closing ln;
// this method will also close it when ctx is done.
func (s *Server) ListenAndServeOn(ctx context.Context, ln net.Listener) error {
	signer, err := s.loadOrGenerateHostKey()
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}

	config := &gossh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
	}
	config.AddHostKey(signer)

	s.logger.Printf("SSH server listening on %s", ln.Addr())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		tcpConn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			s.logger.Printf("accept error: %v", err)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConnection(ctx, tcpConn, config)
		}()
	}

	wg.Wait()
	return ctx.Err()
}

// ListenAndServe starts the SSH server and blocks until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	signer, err := s.loadOrGenerateHostKey()
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}

	config := &gossh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
	}
	config.AddHostKey(signer)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = ln.Close() }()

	s.logger.Printf("SSH server listening on %s", s.listenAddr)

	// Close the listener when the context is canceled so Accept unblocks.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		tcpConn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			s.logger.Printf("accept error: %v", err)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConnection(ctx, tcpConn, config)
		}()
	}

	wg.Wait()
	return ctx.Err()
}

// publicKeyCallback is used as the ServerConfig.PublicKeyCallback.
// It checks admin keys first, then client keys, storing the role in
// Permissions.Extensions.
func (s *Server) publicKeyCallback(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
	ctx := context.Background()

	// --- flag-based admin (always active while flag is set) ---
	if s.flagAdminKey != nil {
		if keysEqual(s.flagAdminKey.Marshal(), key.Marshal()) {
			return &gossh.Permissions{
				Extensions: map[string]string{
					permRole: roleAdmin,
				},
			}, nil
		}
	}

	// --- admin keys ---
	adminKeys, err := s.repo.ListAdminKeys(ctx)
	if err != nil {
		s.logger.Printf("auth: failed to list admin keys: %v", err)
		return nil, fmt.Errorf("internal error")
	}

	offeredBytes := key.Marshal()
	for _, raw := range adminKeys {
		pub, _, _, _, parseErr := gossh.ParseAuthorizedKey([]byte(raw))
		if parseErr != nil {
			continue
		}
		if keysEqual(pub.Marshal(), offeredBytes) {
			return &gossh.Permissions{
				Extensions: map[string]string{
					permRole: roleAdmin,
				},
			}, nil
		}
	}

	// --- client keys ---
	client, err := findClientByKey(s.repo, key)
	if err != nil {
		s.logger.Printf("auth: client key lookup error: %v", err)
		return nil, fmt.Errorf("internal error")
	}
	if client != nil {
		return &gossh.Permissions{
			Extensions: map[string]string{
				permRole:      roleClient,
				"client_name": client.Name,
			},
		}, nil
	}

	return nil, fmt.Errorf("unknown public key for %s", conn.User())
}

// handleConnection performs the SSH handshake and dispatches channels.
func (s *Server) handleConnection(ctx context.Context, tcpConn net.Conn, config *gossh.ServerConfig) {
	defer func() { _ = tcpConn.Close() }()

	sshConn, chans, globalReqs, err := gossh.NewServerConn(tcpConn, config)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			s.logger.Printf("handshake error from %s: %v", tcpConn.RemoteAddr(), err)
		}
		return
	}
	defer func() { _ = sshConn.Close() }()

	s.logger.Printf("connection from %s (%s, role=%s)",
		sshConn.RemoteAddr(), sshConn.User(),
		sshConn.Permissions.Extensions["role"])

	// Discard global requests (keepalive, etc.).
	go gossh.DiscardRequests(globalReqs)

	// Close the connection when the context is done.
	go func() {
		select {
		case <-ctx.Done():
			_ = sshConn.Close()
		case <-waitConn(sshConn):
		}
	}()

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(gossh.UnknownChannelType, "unsupported channel type")
			continue
		}

		channel, reqs, err := newChan.Accept()
		if err != nil {
			s.logger.Printf("channel accept error: %v", err)
			continue
		}

		go s.handleChannel(sshConn, channel, reqs)
	}
}

// handleChannel dispatches a session channel to either the admin TUI handler
// or the client proxy handler based on the role stored during authentication.
func (s *Server) handleChannel(conn *gossh.ServerConn, channel gossh.Channel, reqs <-chan *gossh.Request) {
	role := conn.Permissions.Extensions[permRole]

	switch role {
	case roleAdmin:
		s.adminHandler(channel, reqs, conn, s.repo)
	case roleClient:
		handleClientSession(channel, reqs, conn, s.repo, s.proxier, s.logger)
	default:
		s.logger.Printf("unknown role %q for %s", role, conn.User())
		_, _ = fmt.Fprintf(channel, "access denied\r\n")
		_ = channel.Close()
	}
}

// loadOrGenerateHostKey loads an ED25519 host key from disk, or generates and
// persists a new one if the file does not exist.
func (s *Server) loadOrGenerateHostKey() (gossh.Signer, error) {
	data, err := os.ReadFile(s.hostKeyPath)
	if err == nil {
		return gossh.ParsePrivateKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading host key: %w", err)
	}

	// Generate a new ED25519 key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}

	pemBlock, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(s.hostKeyPath, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("writing host key: %w", err)
	}

	s.logger.Printf("generated new ED25519 host key at %s", s.hostKeyPath)
	return gossh.ParsePrivateKey(pemBytes)
}

// waitConn returns a channel that closes when the SSH connection is closed.
func waitConn(conn *gossh.ServerConn) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		conn.Wait() //nolint:errcheck // Wait returns after connection closes; error is not actionable
		close(ch)
	}()
	return ch
}
