package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"proxpass/internal/models"

	gossh "golang.org/x/crypto/ssh"
)

// -------------------------------------------------------------------------
// parseModes unit tests
// -------------------------------------------------------------------------

// modeBytes encodes (opcode, uint32 value) pairs followed by TTY_OP_END (0x00).
func modeBytes(pairs ...uint32) []byte {
	var buf []byte
	for i := 0; i < len(pairs)-1; i += 2 {
		buf = append(buf, byte(pairs[i]))
		var b4 [4]byte
		binary.BigEndian.PutUint32(b4[:], pairs[i+1])
		buf = append(buf, b4[:]...)
	}
	buf = append(buf, 0) // TTY_OP_END
	return buf
}

func TestParseModes(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantModes gossh.TerminalModes
	}{
		{
			name:      "nil slice",
			data:      nil,
			wantModes: gossh.TerminalModes{},
		},
		{
			name:      "empty slice",
			data:      []byte{},
			wantModes: gossh.TerminalModes{},
		},
		{
			name:      "only TTY_OP_END",
			data:      []byte{0},
			wantModes: gossh.TerminalModes{},
		},
		{
			name: "ECHO and ICRNL",
			data: modeBytes(uint32(gossh.ECHO), 1, uint32(gossh.ICRNL), 1),
			wantModes: gossh.TerminalModes{
				gossh.ECHO:  1,
				gossh.ICRNL: 1,
			},
		},
		{
			name: "multiple modes",
			data: modeBytes(
				uint32(gossh.ECHO), 1,
				uint32(gossh.ICRNL), 1,
				uint32(gossh.OCRNL), 1,
			),
			wantModes: gossh.TerminalModes{
				gossh.ECHO:  1,
				gossh.ICRNL: 1,
				gossh.OCRNL: 1,
			},
		},
		{
			// Valid first entry then only 4 trailing bytes instead of 5 - loop stops.
			name: "incomplete trailing entry is ignored",
			data: func() []byte {
				b := modeBytes(uint32(gossh.ECHO), 1) // includes TTY_OP_END
				b = b[:len(b)-1]                      // strip TTY_OP_END
				b = append(b, byte(gossh.ICRNL), 0, 0, 0) // only 4 bytes
				return b
			}(),
			wantModes: gossh.TerminalModes{
				gossh.ECHO: 1,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseModes(tc.data)
			if len(got) != len(tc.wantModes) {
				t.Fatalf("len(modes) = %d, want %d; got %v", len(got), len(tc.wantModes), got)
			}
			for k, want := range tc.wantModes {
				if got[k] != want {
					t.Errorf("modes[%d] = %d, want %d", k, got[k], want)
				}
			}
		})
	}
}

// -------------------------------------------------------------------------
// proxyToGuest integration tests
//
// These tests spin up an in-process SSH server that records whether a
// pty-req was received and with what parameters, then verify proxyToGuest
// always requests a PTY and correctly forwards terminal modes.
// -------------------------------------------------------------------------

type ptySeenEvent struct {
	requested bool
	term      string
	width     int
	height    int
	modes     gossh.TerminalModes
}

// startMockProxmoxSSH runs a minimal in-process SSH server that:
//   - accepts any public key
//   - records pty-req parameters
//   - replies to shell/exec then closes the session immediately
//
// Returns a ProxmoxInstance pointing at the mock, and a channel that receives
// one ptySeenEvent per session (buffered 256).
func startMockProxmoxSSH(t *testing.T) (*models.ProxmoxInstance, <-chan ptySeenEvent) {
	t.Helper()

	// Host key (throwaway)
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	// Client key (used by proxyToGuest to auth; mock accepts anything)
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientKeyPEM, err := gossh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}

	srvCfg := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, _ gossh.PublicKey) (*gossh.Permissions, error) {
			return &gossh.Permissions{}, nil // accept any key
		},
	}
	srvCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ptyCh := make(chan ptySeenEvent, 256)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			tcpConn, err := ln.Accept()
			if err != nil {
				return
			}
			go mockHandleConn(tcpConn, srvCfg, ptyCh)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	host, portS, _ := net.SplitHostPort(ln.Addr().String())
	var portInt int
	fmt.Sscanf(portS, "%d", &portInt)

	inst := &models.ProxmoxInstance{
		SSHHost: host,
		SSHPort: portInt,
		SSHUser: "root",
		SSHKey:  string(pem.EncodeToMemory(clientKeyPEM)),
	}
	return inst, ptyCh
}

func mockHandleConn(tcpConn net.Conn, srvCfg *gossh.ServerConfig, ptyCh chan<- ptySeenEvent) {
	defer func() { _ = tcpConn.Close() }()
	sshConn, chans, reqs, err := gossh.NewServerConn(tcpConn, srvCfg)
	if err != nil {
		return
	}
	defer func() { _ = sshConn.Close() }()
	go gossh.DiscardRequests(reqs)

	for newChan := range chans {
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer func() { _ = ch.Close() }()
			var seen ptySeenEvent
			for req := range chReqs {
				switch req.Type {
				case "pty-req":
					seen.requested = true
					if p, err := parsePtyReq(req.Payload); err == nil {
						seen.term = p.Term
						seen.width = int(p.Width)
						seen.height = int(p.Height)
						seen.modes = parseModes(p.Modes)
					}
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				case "exec", "shell":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					ptyCh <- seen
					return
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}()
	}
}

// fakeChannel is a minimal gossh.Channel that returns EOF on Read and
// discards all writes - simulating a client that immediately disconnected.
type fakeChannel struct{}

func (*fakeChannel) Read([]byte) (int, error)                          { return 0, io.EOF }
func (*fakeChannel) Write(b []byte) (int, error)                       { return len(b), nil }
func (*fakeChannel) Close() error                                       { return nil }
func (*fakeChannel) CloseWrite() error                                  { return nil }
func (*fakeChannel) SendRequest(_ string, _ bool, _ []byte) (bool, error) { return false, nil }
func (*fakeChannel) Stderr() io.ReadWriter {
	return struct {
		io.Reader
		io.Writer
	}{
		Reader: eofReader{},
		Writer: io.Discard,
	}
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// TestProxyToGuestAlwaysRequestsPTY confirms that proxyToGuest requests a PTY
// on the Proxmox SSH session for both CT and VM guests even when the client
// provided no pty-req (ptyReq == nil).
func TestProxyToGuestAlwaysRequestsPTY(t *testing.T) {
	inst, ptyCh := startMockProxmoxSSH(t)

	guests := []*models.Guest{
		{Name: "test-ct", Type: models.GuestTypeCT, ProxmoxID: 100},
		{Name: "test-vm", Type: models.GuestTypeVM, ProxmoxID: 200},
	}

	for _, guest := range guests {
		guest := guest
		t.Run(string(guest.Type), func(t *testing.T) {
			reqs := make(chan *gossh.Request)
			close(reqs)
			_ = proxyToGuest(&fakeChannel{}, reqs, guest, inst, nil /*no pty*/, nil)

			select {
			case seen := <-ptyCh:
				if !seen.requested {
					t.Errorf("%s: PTY not requested on Proxmox session", guest.Type)
				}
				if seen.term == "" {
					t.Errorf("%s: PTY term is empty", guest.Type)
				}
				if seen.width <= 0 {
					t.Errorf("%s: PTY width = %d, want > 0", guest.Type, seen.width)
				}
				if seen.height <= 0 {
					t.Errorf("%s: PTY height = %d, want > 0", guest.Type, seen.height)
				}
			default:
				t.Errorf("%s: no PTY event received from mock server", guest.Type)
			}
		})
	}
}

// TestProxyToGuestForwardsModes checks that when the client provides a pty-req
// with non-empty modes, those modes are forwarded to the Proxmox SSH session.
func TestProxyToGuestForwardsModes(t *testing.T) {
	inst, ptyCh := startMockProxmoxSSH(t)

	modes := modeBytes(uint32(gossh.ECHO), 1, uint32(gossh.ICRNL), 1)
	ptyReq := &PtyRequest{Term: "xterm", Width: 120, Height: 40, Modes: modes}

	guest := &models.Guest{Name: "test-ct", Type: models.GuestTypeCT, ProxmoxID: 100}
	reqs := make(chan *gossh.Request)
	close(reqs)
	_ = proxyToGuest(&fakeChannel{}, reqs, guest, inst, ptyReq, nil)

	select {
	case seen := <-ptyCh:
		if !seen.requested {
			t.Fatal("PTY not requested")
		}
		if seen.term != "xterm" {
			t.Errorf("term = %q, want xterm", seen.term)
		}
		if seen.modes[gossh.ECHO] != 1 {
			t.Errorf("ECHO = %d, want 1", seen.modes[gossh.ECHO])
		}
		if seen.modes[gossh.ICRNL] != 1 {
			t.Errorf("ICRNL = %d, want 1", seen.modes[gossh.ICRNL])
		}
	default:
		t.Fatal("no PTY event received from mock server")
	}
}
