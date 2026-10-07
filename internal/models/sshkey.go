package models

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// DefaultSSHKeyPath is where the container entrypoint writes the private key
// proxpass uses to reach Proxmox hosts over the ssh connection type.
//
// One key for the whole deployment, not one per instance: its public half has
// to be installed on each Proxmox host by hand, and a key per instance
// multiplies that work without isolating anything.
//
// It is a FILE rather than a row in the database, and that is deliberate on
// two counts:
//
//   - The administrator can read the public half at any time to install it,
//     without proxpass having to offer a command that prints a private key.
//   - The database is reachable from an admin session through GetSetting on
//     /admin/rpc. Storing the key there would put a Proxmox credential back
//     within reach of a session, which is exactly what moving sessions onto
//     the API was meant to stop.
//
// The entrypoint generates it on the volume when it is absent, so recreating
// the container does not invalidate the key already installed on every host.
// PROXPASS_SSH_KEY_FILE overrides the location for a deployment that mounts
// its own key.
//
// Kept in sync with docker/entrypoint.sh by
// TestEntrypointDefaultsToTheSSHKeyPath.
const DefaultSSHKeyPath = "/var/lib/proxpass/ssh/proxpass_key"

// SSHKeyPathEnv names the environment variable that overrides
// DefaultSSHKeyPath.
//
// Read by `proxpass serve' -- which is the only process that opens the key --
// and set by the entrypoint. A session never sees it: sshd scrubs the
// environment, and the session is handed the key contents by the API after
// its access check rather than reading the file itself. It could not read it
// anyway, since the file is root-owned and the session is not root.
const SSHKeyPathEnv = "PROXPASS_SSH_KEY_FILE"

// SSHKeyPath returns where the deployment's Proxmox key lives.
func SSHKeyPath() string {
	if p := os.Getenv(SSHKeyPathEnv); p != "" {
		return p
	}
	return DefaultSSHKeyPath
}

// ReadSSHKey returns the PEM private key proxpass uses to reach Proxmox hosts
// over the ssh connection type, or "" when the deployment has none.
//
// A missing file is NOT an error. A deployment that only uses termproxy never
// needs the key, and reporting its absence here would break those connections
// over something they do not use. The callers that need a key check for the
// empty string and say what to do about it, which this function cannot: it
// does not know whether the caller is adding an instance or opening a console.
func ReadSSHKey() (string, error) {
	path := SSHKeyPath()
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading the proxpass ssh key %s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}
