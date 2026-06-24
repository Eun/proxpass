package proxmox

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"proxpass/internal/models"
)

// Client holds an SSH connection to a single Proxmox host and exposes
// methods to discover guests running on that host.
type Client struct {
	inst   *models.ProxmoxInstance
	sshCli *ssh.Client
}

// NewClient connects to the Proxmox host described by inst using the SSH
// private key located at inst.APIKey.
func NewClient(inst *models.ProxmoxInstance) (*Client, error) {
	keyBytes, err := os.ReadFile(inst.APIKey)
	if err != nil {
		return nil, fmt.Errorf("read ssh key %s: %w", inst.APIKey, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ssh key %s: %w", inst.APIKey, err)
	}

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := net.JoinHostPort(inst.Hostname, strconv.Itoa(inst.Port))
	sshCli, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	return &Client{inst: inst, sshCli: sshCli}, nil
}

// DiscoverGuests runs `pct list` and `qm list` on the Proxmox host and
// returns the combined set of Guest structs.
func (c *Client) DiscoverGuests() ([]*models.Guest, error) {
	var guests []*models.Guest

	// --- LXC containers via pct list ---
	pctOut, err := c.runCommand("pct list")
	if err != nil {
		return nil, fmt.Errorf("pct list: %w", err)
	}
	cts, err := parsePctList(pctOut)
	if err != nil {
		return nil, fmt.Errorf("parse pct list: %w", err)
	}
	guests = append(guests, cts...)

	// --- QEMU VMs via qm list ---
	qmOut, err := c.runCommand("qm list")
	if err != nil {
		return nil, fmt.Errorf("qm list: %w", err)
	}
	vms, err := parseQmList(qmOut)
	if err != nil {
		return nil, fmt.Errorf("parse qm list: %w", err)
	}
	guests = append(guests, vms...)

	return guests, nil
}

// Close closes the underlying SSH connection.
func (c *Client) Close() error {
	return c.sshCli.Close()
}

// runCommand executes a command on the remote host and returns the combined
// stdout output as a string.
func (c *Client) runCommand(cmd string) (string, error) {
	sess, err := c.sshCli.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	out, err := sess.CombinedOutput(cmd)
	if err != nil {
		return "", fmt.Errorf("run %q: %w (output: %s)", cmd, err, string(out))
	}
	return string(out), nil
}

// parsePctList parses the tabular output of `pct list`.
//
// Expected format:
//
//	VMID       Status     Lock         Name
//	100        running                 mycontainer
//	101        stopped                 another
func parsePctList(output string) ([]*models.Guest, error) {
	var guests []*models.Guest
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) <= 1 {
		// Header only or empty — no containers.
		return guests, nil
	}

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		vmid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		status := normalizeStatus(fields[1])

		// Name is the last field; the Lock column may be empty, which
		// causes the field count to vary.
		name := fields[len(fields)-1]

		guests = append(guests, &models.Guest{
			Type:      models.GuestTypeCT,
			ProxmoxID: vmid,
			Name:      name,
			Status:    status,
		})
	}
	return guests, nil
}

// parseQmList parses the tabular output of `qm list`.
//
// Expected format:
//
//	      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID
//	       200 myvm                 running    2048              32.00 12345
//	       201 othervm              stopped    1024              20.00 0
func parseQmList(output string) ([]*models.Guest, error) {
	var guests []*models.Guest
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) <= 1 {
		return guests, nil
	}

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		vmid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		name := fields[1]
		status := normalizeStatus(fields[2])

		guests = append(guests, &models.Guest{
			Type:      models.GuestTypeVM,
			ProxmoxID: vmid,
			Name:      name,
			Status:    status,
		})
	}
	return guests, nil
}

// normalizeStatus maps a raw status string to one of the known Status
// constants. Unknown values default to StatusStopped.
func normalizeStatus(raw string) models.Status {
	switch strings.ToLower(raw) {
	case "running":
		return models.StatusRunning
	case "stopped":
		return models.StatusStopped
	default:
		return models.StatusStopped
	}
}
