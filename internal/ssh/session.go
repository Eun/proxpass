package ssh

import (
	"context"
	"encoding/binary"
	"fmt"

	"proxpass/internal/db"
	"proxpass/internal/models"

	gossh "golang.org/x/crypto/ssh"
)

// ptyRequest holds the parsed fields of an SSH "pty-req" request.
type ptyRequest struct {
	Term   string
	Width  uint32
	Height uint32
	Modes  []byte
}

// parsePtyReq parses the payload of an SSH "pty-req" channel request.
// Wire format (RFC 4254 §6.2):
//
//	string  term
//	uint32  width  (columns)
//	uint32  height (rows)
//	uint32  pixel width
//	uint32  pixel height
//	string  encoded terminal modes
func parsePtyReq(data []byte) (*ptyRequest, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("pty-req payload too short")
	}

	// term (string = uint32 len + bytes)
	termLen := binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	if uint32(len(data)) < termLen { //nolint:gosec // length bounded by protocol
		return nil, fmt.Errorf("pty-req: term length exceeds payload")
	}
	term := string(data[:termLen])
	data = data[termLen:]

	// width, height, pixel_width, pixel_height  (4 × uint32 = 16 bytes)
	if len(data) < 16 {
		return nil, fmt.Errorf("pty-req: missing dimension fields")
	}
	width := binary.BigEndian.Uint32(data[0:4])
	height := binary.BigEndian.Uint32(data[4:8])
	// pixel width and height are at data[8:16]; we skip them.
	data = data[16:]

	// modes (string)
	var modes []byte
	if len(data) >= 4 {
		modesLen := binary.BigEndian.Uint32(data[0:4])
		data = data[4:]
		if uint32(len(data)) >= modesLen { //nolint:gosec // length bounded by protocol
			modes = make([]byte, modesLen)
			copy(modes, data[:modesLen])
		}
	}

	return &ptyRequest{
		Term:   term,
		Width:  width,
		Height: height,
		Modes:  modes,
	}, nil
}

// parseWindowChange parses the payload of an SSH "window-change" channel
// request.  Wire format (RFC 4254 §6.7):
//
//	uint32  columns
//	uint32  rows
//	uint32  pixel width
//	uint32  pixel height
func parseWindowChange(data []byte) (width, height uint32, err error) {
	if len(data) < 8 {
		return 0, 0, fmt.Errorf("window-change payload too short")
	}
	width = binary.BigEndian.Uint32(data[0:4])
	height = binary.BigEndian.Uint32(data[4:8])
	return width, height, nil
}

// findClientByKey searches every client in the database for one whose stored
// public keys contain a key matching the offered key. Returns nil, nil when no
// match is found.
func findClientByKey(repo db.Repository, key gossh.PublicKey) (*models.Client, error) {
	ctx := context.Background()

	clients, err := repo.ListClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
	}

	offeredBytes := key.Marshal()

	for _, c := range clients {
		for _, raw := range c.PublicKeys {
			pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(raw))
			if err != nil {
				continue
			}
			if keysEqual(pub.Marshal(), offeredBytes) {
				return c, nil
			}
		}
	}
	return nil, nil
}

// keysEqual compares two marshaled public key byte slices.
func keysEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
