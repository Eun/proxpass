# ProxPass

A standalone SSH proxy for Proxmox VE that routes client connections to LXC containers and QEMU virtual machines. Administrators manage access through a CLI delivered over SSH.

## Features

- **SSH Proxy** — Clients SSH in and are transparently proxied to Proxmox guests (`pct enter` for containers, `qm terminal` for VMs)
- **Public Key Authentication** — Both admin and client access is controlled via SSH public keys
- **Auto-Discovery** — Periodically discovers containers and VMs from configured Proxmox hosts via the REST API
- **Admin CLI over SSH** — Full command-line interface for managing instances, clients, groups, access rules, and admin keys
- **Flexible Guest Resolution** — Connect by VMID (`ssh 100@host`), type+VMID (`ssh ct100@host`), or name (`ssh webserver@host`)
- **Access Control** — Per-client and per-group access rules with a global default policy fallback
- **SQLite Storage** — Single-file embedded database, no external dependencies

## Quick Start

```bash
# Build
mise run build

# Run with a flag-based admin key
./proxpass --admin-key "$(cat ~/.ssh/id_ed25519.pub)"

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
# Add with an explicit name (single --url only)
ssh -p 2222 admin@proxpass instance add \
  --name pve1 \
  --url https://pve:8006 \
  --token-id "user@pam!token" \
  --token-secret "uuid" \
  --ssh-host pve1 \
  --ssh-key-path /root/.ssh/id_ed25519

# --name is optional; when omitted, the Proxmox node name is used automatically
ssh -p 2222 admin@proxpass instance add \
  --url https://pve:8006 \
  --token-id "user@pam!token" \
  --token-secret "uuid"

# Add multiple instances in one call — --name is disallowed with multiple --url
# Each instance is named after its Proxmox node name automatically
ssh -p 2222 admin@proxpass instance add \
  --url https://pve1:8006 \
  --url https://pve2:8006 \
  --url https://pve3:8006 \
  --token-id "user@pam!token" \
  --token-secret "uuid"

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
| `--listen` | `PROXPASS_LISTEN` | `:2222` | SSH listen address |
| `--host-key` | `PROXPASS_HOST_KEY` | `./proxpass_host_key` | Path to ED25519 host key (auto-generated if missing) |
| `--data` | `PROXPASS_DATA` | `./proxpass.db` | Path to SQLite database |
| `--discovery-interval` | `PROXPASS_DISCOVERY_INTERVAL` | `5m` | Guest discovery poll interval |
| `--log-level` | `PROXPASS_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `--admin-key` | `PROXPASS_ADMIN_KEY` | | Flag-based admin public key (see below) |

### Flag-based admin key

The `--admin-key` flag accepts an SSH public key in `authorized_keys` format. When set, this key is treated as an admin key **for the lifetime of the process**, checked before any database lookup. Users are identified solely by their public key — the SSH username is not used for authentication.

## Client Connections

Clients connect using the guest identifier as the SSH username:

```bash
# By VMID
ssh -p 2222 100@proxpass-host

# By type+VMID (disambiguates collisions)
ssh -p 2222 ct100@proxpass-host
ssh -p 2222 vm200@proxpass-host

# By name (case-insensitive)
ssh -p 2222 webserver@proxpass-host
```

## Architecture

```
proxpass/
├── cmd/proxpass/          # CLI entry point (urfave/cli v3)
├── cmd/proxmox-mock/      # Mock Proxmox service for testing
└── internal/
    ├── cli/               # Admin CLI commands
    ├── models/            # Data types
    ├── db/                # SQLite repository
    ├── proxmox/           # Proxmox API client & discovery
    ├── ssh/               # SSH server, auth, proxy
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
