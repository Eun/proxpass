# ProxPass

An SSH proxy for Proxmox VE that routes client connections to LXC containers and QEMU virtual machines. Administrators manage access through a CLI delivered over SSH.

ProxPass ships as a single Docker image containing OpenSSH `sshd` and the
proxpass binary. It does **not** implement its own SSH server: sshd owns the
protocol, and proxpass supplies the users, the keys and the session.

## Features

- **Real OpenSSH** — sshd handles the protocol; proxpass only decides who may log in and where they land
- **Public Key Authentication** — The only supported method; password authentication is disabled
- **Auto-Discovery** — Periodically discovers containers and VMs from configured Proxmox hosts via the REST API
- **Admin CLI over SSH** — Full command-line interface for managing instances, clients, groups, access rules, and admin keys
- **Flexible Guest Resolution** — Connect by VMID (`100`), type+VMID (`ct100`), name (`webserver`), or instance-qualified (`rome:ct101`)
- **Access Control** — Per-client and per-group access rules with a global default policy fallback
- **SQLite Storage** — Single-file embedded database, no external dependencies

## How it works

```
ssh alice@proxpass-host ct100
        │
        ▼
     sshd  ──AuthorizedKeysCommand──▶  proxpass authorized-keys alice
        │                                       │
        │   ◀──── alice's public keys ──────────┘
        │
        │   NSS (libnss_http.so.2) ──HTTP──▶  proxpass serve
        │     resolves "alice" to a uid              (directory API)
        ▼
     ForceCommand: proxpass session
        │
        ▼
     Proxmox guest console (termproxy WebSocket, or SSH + pct/qm)
```

Clients are not Unix accounts. sshd resolves them through NSS, which asks the
proxpass directory API over loopback, so all user management stays in the
proxpass database. This requires **glibc** — musl (Alpine) has no NSS support,
which is why the image is Debian based.

## Quick Start

```bash
docker run -d --name proxpass \
  -p 2222:22 \
  -v proxpass-data:/var/lib/proxpass \
  -e PROXPASS_ADMIN_KEY="$(cat ~/.ssh/id_ed25519.pub)" \
  ghcr.io/eun/proxpass:latest

# Connect as admin and view help
ssh -p 2222 admin@localhost
```

## Admin CLI

The admin CLI is accessed over SSH. Commands are passed as the SSH exec command:

```bash
# List all commands
ssh -p 2222 admin@proxpass

# Manage Proxmox instances
ssh -p 2222 admin@proxpass instance ls

# Add a single instance (termproxy — no SSH credentials needed)
ssh -p 2222 admin@proxpass instance add \
  --url https://pve:8006 \
  --token-id "user@pam!token" \
  --token-secret "uuid"

# Add a single instance with SSH connection type.
# --ssh-host is optional: when omitted the hostname from --url is used (pve, port 22).
# An explicit --ssh-host may include a port: --ssh-host pve:2222
ssh -p 2222 admin@proxpass instance add \
  --url https://pve:8006 \
  --token-id "user@pam!token" \
  --token-secret "uuid" \
  --connection-type ssh \
  --ssh-key-path /root/.ssh/id_ed25519

# Override the SSH host/port explicitly (single --url only)
ssh -p 2222 admin@proxpass instance add \
  --name pve1 \
  --url https://pve1:8006 \
  --token-id "user@pam!token" \
  --token-secret "uuid" \
  --connection-type ssh \
  --ssh-host pve1.internal:2222 \
  --ssh-key-path /root/.ssh/id_ed25519

# Add multiple instances in one call.
# --name and --ssh-host are disallowed with multiple --url.
# Each instance is named after its Proxmox node name; SSH host is derived
# from the hostname in each --url (port 22).
ssh -p 2222 admin@proxpass instance add \
  --url https://pve1:8006 \
  --url https://pve2:8006 \
  --url https://pve3:8006 \
  --token-id "user@pam!token" \
  --token-secret "uuid" \
  --connection-type ssh \
  --ssh-key-path /root/.ssh/id_ed25519

ssh -p 2222 admin@proxpass instance rm --name pve1

# List and connect to guests
ssh -p 2222 admin@proxpass guest ls
ssh -p 2222 admin@proxpass guest ls --json
ssh -p 2222 admin@proxpass guest connect webserver
ssh -p 2222 admin@proxpass guest connect 100
ssh -p 2222 admin@proxpass guest connect ct100

# Manage clients
ssh -p 2222 admin@proxpass client ls
ssh -p 2222 admin@proxpass client add --name alice \
  --key "ssh-ed25519 AAAA..." --key "ssh-rsa AAAA..."
ssh -p 2222 admin@proxpass client rm --name alice

# Manage groups
ssh -p 2222 admin@proxpass group ls
ssh -p 2222 admin@proxpass group add --name developers \
  --member alice --member bob
ssh -p 2222 admin@proxpass group rm --name developers

# Manage access rules
ssh -p 2222 admin@proxpass access ls
ssh -p 2222 admin@proxpass access grant \
  --client alice --guest webserver
ssh -p 2222 admin@proxpass access grant \
  --group developers --guest devbox
ssh -p 2222 admin@proxpass access revoke \
  --client alice --guest webserver

# Manage default policy
ssh -p 2222 admin@proxpass policy ls
ssh -p 2222 admin@proxpass policy add --client alice
ssh -p 2222 admin@proxpass policy add --group developers
ssh -p 2222 admin@proxpass policy rm --client alice

# Manage admin keys
ssh -p 2222 admin@proxpass admin-key ls
ssh -p 2222 admin@proxpass admin-key add \
  --key "ssh-ed25519 AAAA..."
ssh -p 2222 admin@proxpass admin-key rm \
  --key "ssh-ed25519 AAAA..."

# Trigger discovery manually
ssh -p 2222 admin@proxpass discover
```

All `ls` commands support `--json` for machine-readable output.

## Configuration

All flags can also be set via environment variables.

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--data` | `PROXPASS_DATA` | `/var/lib/proxpass/proxpass.db` | Path to SQLite database |
| `--log-level` | `PROXPASS_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `--admin-key` | `PROXPASS_ADMIN_KEY` | | Admin public key (see below) |
| `--listen` | `PROXPASS_LISTEN` | `127.0.0.1:8080` | Address of the NSS directory API (`serve` only) |
| `--discovery-interval` | `PROXPASS_DISCOVERY_INTERVAL` | `5m` | Guest discovery poll interval (`serve` only) |

The SSH port itself is sshd's, so it is published with `-p` on the container
rather than configured in proxpass.

### Admin key

`--admin-key` accepts an SSH public key in `authorized_keys` format. It is
offered for the reserved `admin` login **for the lifetime of the process**, in
addition to any keys in the database. It is never offered for a client login.

### Subcommands

| Command | Invoked by | Purpose |
|---------|-----------|---------|
| `proxpass serve` | container entrypoint | Guest discovery + the NSS directory API |
| `proxpass authorized-keys <user>` | sshd `AuthorizedKeysCommand` | Prints the user's public keys |
| `proxpass session` | sshd `ForceCommand` | Runs the client's session |

## Client Connections

Log in as your client name. The guest identifier is passed as the SSH command;
with no command you get an interactive picker. A PTY (`-t`) is required when
naming a guest directly.

```bash
# Interactive picker
ssh -p 2222 alice@proxpass-host

# By VMID
ssh -t -p 2222 alice@proxpass-host 100

# By type+VMID (disambiguates collisions)
ssh -t -p 2222 alice@proxpass-host ct100
ssh -t -p 2222 alice@proxpass-host vm200

# By name (case-insensitive)
ssh -t -p 2222 alice@proxpass-host webserver

# With an instance prefix (when the same VMID exists on multiple nodes)
ssh -t -p 2222 alice@proxpass-host rome:ct101
```

Add this to `~/.ssh/config` to avoid typing `-t` every time:

```
Host proxpass-host
    Port 2222
    User alice
    RequestTTY yes
```

## Architecture

```
proxpass/
├── cmd/proxpass/          # CLI entry point (serve, authorized-keys, session)
├── cmd/proxmox-mock/      # Mock Proxmox service for testing
├── docker/                # Entrypoint and sshd/NSS configuration
└── internal/
    ├── api/               # NSS directory API consumed by libnss_http
    ├── cli/               # Admin CLI commands
    ├── console/           # Guest console transports (termproxy, ssh)
    ├── db/                # SQLite repository
    ├── models/            # Data types
    ├── proxmox/           # Proxmox API client & discovery
    ├── session/           # Login session: auth, routing, picker
    └── testenv/           # Test infrastructure & mocks
```

## Access Control

Access is checked in order:

1. **Explicit client rule** — client is directly granted access to the guest
2. **Group rule** — client belongs to a group that is granted access to the guest
3. **Default policy** — client or their group is listed in the global default policy

## Development

```bash
# Install tooling (Go, golangci-lint, goreleaser)
mise install

# Run tests
mise run test

# Lint
mise run lint

# Build
mise run build

# Run mock Proxmox service
mise run mock

# Snapshot release (local only)
mise run release

# Clean build artifacts
mise run clean
```
