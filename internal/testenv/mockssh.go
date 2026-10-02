package testenv

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"proxpass/internal/console"
	"proxpass/internal/models"

	gossh "golang.org/x/crypto/ssh"
)

// MockSSHServer simulates a Proxmox host's SSH server.
// It accepts exec requests for "pct enter N" and "qm terminal N"
// and echoes back input prefixed with the guest info.
type MockSSHServer struct {
	listener net.Listener
	config   *gossh.ServerConfig
	signer   gossh.Signer
	wg       sync.WaitGroup
	done     chan struct{}

	// Host returns the listen host.
	Host string
	// Port returns the listen port.
	Port int
	// KeyPath is the path to a temp file containing the private
	// key that clients should use to authenticate.
	KeyPath string
	// User is the SSH username the server expects.
	User string
}

// NewMockSSHServer starts a mock SSH server on a random port.
// It generates an ED25519 keypair; the private key is written to a
// temp file whose path is available as KeyPath. Callers must call
// Close() to clean up.
func NewMockSSHServer() (*MockSSHServer, error) {
	// Generate server host key
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostPriv)
	if err != nil {
		return nil, fmt.Errorf("host signer: %w", err)
	}

	// Generate client keypair and write private key to temp file
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate client key: %w", err)
	}

	pemBlock, err := gossh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal client key: %w", err)
	}
	keyFile, err := os.CreateTemp("", "proxpass-test-key-*")
	if err != nil {
		return nil, fmt.Errorf("temp file: %w", err)
	}
	_ = pem.Encode(keyFile, pemBlock)
	_ = keyFile.Close()

	// Server config — accept the generated client public key
	clientSSHPub, err := gossh.NewPublicKey(clientPub)
	if err != nil {
		return nil, fmt.Errorf("client ssh pub: %w", err)
	}
	expectedPubBytes := clientSSHPub.Marshal()

	config := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if bytes.Equal(key.Marshal(), expectedPubBytes) {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	config.AddHostKey(hostSigner)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	addr := ln.Addr().(*net.TCPAddr)
	m := &MockSSHServer{
		listener: ln,
		config:   config,
		signer:   hostSigner,
		done:     make(chan struct{}),
		Host:     "127.0.0.1",
		Port:     addr.Port,
		KeyPath:  keyFile.Name(),
		User:     defaultSSHUser,
	}

	m.wg.Add(1)
	go m.serve()

	return m, nil
}

func (m *MockSSHServer) serve() {
	defer m.wg.Done()
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			select {
			case <-m.done:
				return
			default:
				continue
			}
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.handleConn(conn)
		}()
	}
}

func (m *MockSSHServer) handleConn(netConn net.Conn) {
	defer func() { _ = netConn.Close() }()

	sshConn, chans, reqs, err := gossh.NewServerConn(netConn, m.config)
	if err != nil {
		return
	}
	defer func() { _ = sshConn.Close() }()
	go gossh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(gossh.UnknownChannelType, "unsupported")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			continue
		}
		go m.handleSession(ch, requests)
	}
}

//nolint:gocognit // mock SSH session handler covers multiple request types
func (m *MockSSHServer) handleSession(ch gossh.Channel, reqs <-chan *gossh.Request) {
	defer func() { _ = ch.Close() }()

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			// Parse command from payload: uint32 len + string
			if len(req.Payload) < 4 {
				return
			}
			cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
			if len(req.Payload) < 4+cmdLen {
				return
			}
			cmd := string(req.Payload[4 : 4+cmdLen])
			m.handleExecCommand(ch, cmd)
			return

		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			_, _ = fmt.Fprintf(ch, "[mock] interactive shell\r\n")
			buf := make([]byte, 1024)
			for {
				n, err := ch.Read(buf)
				if n > 0 {
					_, _ = ch.Write(buf[:n])
				}
				if err != nil {
					break
				}
			}
			exitMsg := gossh.Marshal(struct{ Status uint32 }{0})
			_, _ = ch.SendRequest("exit-status", false, exitMsg)
			return

		case "window-change":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// handleExecCommand responds to pct enter / qm terminal commands
// with a realistic mock console session.
func (m *MockSSHServer) handleExecCommand(ch gossh.Channel, cmd string) {
	parts := strings.Fields(cmd)

	switch {
	case len(parts) == 3 && parts[0] == "pct" && parts[1] == "enter":
		vmid := parts[2]
		_, _ = fmt.Fprintf(ch,
			"entering LXC container %s\r\n"+
				"Type 'exit' or press Ctrl+D to disconnect.\r\n"+
				"\r\n"+
				"root@CT%s:~# ", vmid, vmid)
		switch vmid {
		case strconv.Itoa(WedgedVMID):
			m.wedgedSession(ch)
		case strconv.Itoa(AltScreenVMID):
			m.altScreenSession(ch)
		default:
			m.lxcSession(ch, vmid)
		}

	case len(parts) == 3 && parts[0] == "qm" && parts[1] == "terminal":
		vmid := parts[2]
		_, _ = fmt.Fprintf(ch,
			"starting serial terminal on VM %s\r\n"+
				"Press Ctrl+] to disconnect.\r\n"+
				"\r\n"+
				"login: ", vmid)
		m.vmSession(ch)

	default:
		_, _ = fmt.Fprintf(ch,
			"[mock] unknown command: %s\r\n", cmd)
	}

	exitMsg := gossh.Marshal(struct{ Status uint32 }{0})
	_, _ = ch.SendRequest("exit-status", false, exitMsg)
}

// WedgedVMID is a guest whose console never exits on its own. Entering it
// runs a session that ignores stdin entirely -- no EOF handling, no exit
// command -- standing in for a hung process or a full-screen application.
// Only closing the channel ends it, which is what the Ctrl+A X escape hatch
// has to do to be worth anything.
const WedgedVMID = 999

// AltScreenVMID is a guest whose console immediately switches to the
// alternate screen buffer, as vim, top and less do. It stands in for a
// full-screen application so the status bar's hiding behavior can be tested
// without one installed in the mock.
const AltScreenVMID = 998

// altScreenSession enters the alternate screen, echoes input, and leaves it
// when the user sends "q".
func (m *MockSSHServer) altScreenSession(ch gossh.Channel) {
	// Switch to the alternate screen and draw something, the way a
	// full-screen application would.
	_, _ = fmt.Fprintf(ch, "\x1b[?1049h\x1b[H\x1b[2J[fullscreen app] press q to quit\r\n")
	buf := make([]byte, 1)
	for {
		n, err := ch.Read(buf)
		if err != nil || n == 0 {
			break
		}
		if buf[0] == 'q' {
			break
		}
	}
	// Restore the primary screen on exit.
	_, _ = fmt.Fprintf(ch, "\x1b[?1049l\r\n[left fullscreen]\r\n")
}

// wedgedSession blocks until the channel is closed, discarding input.
func (m *MockSSHServer) wedgedSession(ch gossh.Channel) {
	buf := make([]byte, 64)
	for {
		if _, err := ch.Read(buf); err != nil {
			// Only a channel close or transport failure gets us here;
			// stdin EOF alone does not, because the client half-closing
			// its write side does not surface as a read error.
			return
		}
	}
}

// lxcSession simulates a pct enter session. It collects input
// line-by-line, echoes characters, and exits when the user types
// "exit" or sends Ctrl+D (0x04).
func (m *MockSSHServer) lxcSession(ch gossh.Channel, vmid string) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := ch.Read(buf)
		if err != nil || n == 0 {
			return
		}
		b := buf[0]

		switch b {
		case 0x04: // Ctrl+D
			_, _ = fmt.Fprintf(ch, "\r\nlogout\r\n")
			return
		case '\r', '\n':
			_, _ = ch.Write([]byte("\r\n"))
			cmd := strings.TrimSpace(string(line))
			line = line[:0]
			if cmd == "exit" {
				return
			}
			if cmd != "" {
				_, _ = fmt.Fprintf(ch,
					"[mock] %s: command not found\r\n", cmd)
			}
			_, _ = fmt.Fprintf(ch, "root@CT%s:~# ", vmid)
		case 0x0c: // Ctrl+L: clear the screen, as a real shell does
			// ED addresses the whole screen, including a reserved
			// status-bar row, so this is what makes a bar vanish.
			_, _ = fmt.Fprintf(ch, "\x1b[H\x1b[2J")
			_, _ = fmt.Fprintf(ch, "root@CT%s:~# ", vmid)
		case 0x7f, 0x08: // backspace / delete
			if len(line) > 0 {
				line = line[:len(line)-1]
				_, _ = ch.Write([]byte("\b \b"))
			}
		default:
			line = append(line, b)
			_, _ = ch.Write(buf[:1])
		}
	}
}

// vmSession simulates a qm terminal session. It echoes input and
// exits when the user sends Ctrl+] (0x1d).
func (m *MockSSHServer) vmSession(ch gossh.Channel) {
	buf := make([]byte, 1)
	for {
		n, err := ch.Read(buf)
		if err != nil || n == 0 {
			return
		}
		if buf[0] == 0x1d { // Ctrl+]
			_, _ = fmt.Fprintf(ch, "\r\n[disconnected]\r\n")
			return
		}
		_, _ = ch.Write(buf[:1])
	}
}

// Close stops the mock SSH server and removes the temp key file.
func (m *MockSSHServer) Close() {
	close(m.done)
	_ = m.listener.Close()
	m.wg.Wait()
	_ = os.Remove(m.KeyPath)
}

// MockProxier implements console.Proxier without any real connection to a
// Proxmox host. It writes a banner to the terminal and echoes input back.
type MockProxier struct {
	mu       sync.Mutex
	Sessions []MockProxySession
}

// SessionsSnapshot returns a copy of the recorded sessions. Tests may call
// this while a session is still running, so it must hold the lock.
func (p *MockProxier) SessionsSnapshot() []MockProxySession {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]MockProxySession, len(p.Sessions))
	copy(out, p.Sessions)
	return out
}

// MockProxySession records a proxy session that was requested.
type MockProxySession struct {
	GuestName string
	GuestType models.GuestType
	ProxmoxID int
	// InstanceName and InstanceID identify WHICH Proxmox instance the
	// guest was reached on. A VMID is unique per instance but not across
	// them, so these are the only way a test can tell "ct100 on rome"
	// apart from "ct100 on paris".
	InstanceName string
	InstanceID   int64
}

// Connect implements console.Proxier. It records the session, writes a mock
// banner and echoes terminal input until the input stream ends.
func (p *MockProxier) Connect(
	term *console.Terminal,
	guest *models.Guest,
	inst *models.ProxmoxInstance,
	_ *log.Logger,
) error {
	p.mu.Lock()
	p.Sessions = append(p.Sessions, MockProxySession{
		GuestName:    guest.Name,
		GuestType:    guest.Type,
		ProxmoxID:    guest.ProxmoxID,
		InstanceName: inst.Name,
		InstanceID:   inst.ID,
	})
	p.mu.Unlock()

	_, _ = fmt.Fprintf(term.Out, "[mock proxy] connected to %s (%s %d) on %s\r\n",
		guest.Name, guest.Type, guest.ProxmoxID, inst.Name)

	// Echo input back until the terminal closes (simulates a short session).
	buf := make([]byte, 256)
	for {
		n, err := term.In.Read(buf)
		if n > 0 {
			if _, writeErr := term.Out.Write(buf[:n]); writeErr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return nil
}

// NewMockSSHServerOnAddr starts a mock SSH server on the given address
// (e.g. ":2223"). If keyPath is non-empty the generated client private
// key is written there; otherwise a temp file is created. For unit
// tests use NewMockSSHServer which binds to a random port.
func NewMockSSHServerOnAddr(addr, keyPath string) (*MockSSHServer, error) {
	// Generate server host key
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostPriv)
	if err != nil {
		return nil, fmt.Errorf("host signer: %w", err)
	}

	// Generate client keypair and write private key to temp file
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate client key: %w", err)
	}

	pemBlock, err := gossh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal client key: %w", err)
	}
	var keyFilePath string
	if keyPath != "" {
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return nil, fmt.Errorf("write key to %s: %w", keyPath, err)
		}
		keyFilePath = keyPath
	} else {
		keyFile, err := os.CreateTemp("", "proxpass-mock-key-*")
		if err != nil {
			return nil, fmt.Errorf("temp file: %w", err)
		}
		_ = pem.Encode(keyFile, pemBlock)
		_ = keyFile.Close()
		keyFilePath = keyFile.Name()
	}

	// Server config — accept the generated client public key
	clientSSHPub, err := gossh.NewPublicKey(clientPub)
	if err != nil {
		return nil, fmt.Errorf("client ssh pub: %w", err)
	}
	expectedPubBytes := clientSSHPub.Marshal()

	config := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if bytes.Equal(key.Marshal(), expectedPubBytes) {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	config.AddHostKey(hostSigner)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}

	tcpAddr := ln.Addr().(*net.TCPAddr)
	m := &MockSSHServer{
		listener: ln,
		config:   config,
		signer:   hostSigner,
		done:     make(chan struct{}),
		Host:     "127.0.0.1",
		Port:     tcpAddr.Port,
		KeyPath:  keyFilePath,
		User:     defaultSSHUser,
	}

	m.wg.Add(1)
	go m.serve()

	return m, nil
}

// RecordedSessions returns a snapshot of all proxy sessions recorded so far.
// It is safe to call from multiple goroutines.
func (p *MockProxier) RecordedSessions() []MockProxySession {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]MockProxySession, len(p.Sessions))
	copy(out, p.Sessions)
	return out
}

// Compile-time check.
var _ console.Proxier = (*MockProxier)(nil)
