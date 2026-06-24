# ProxPass

A standalone SSH proxy for Proxmox VE that routes client connections to LXC containers and QEMU virtual machines. Administrators manage access through an interactive TUI delivered over SSH.

## Features

- **SSH Proxy** — Clients SSH in and are transparently proxied to Proxmox guests (`pct enter` for containers, `qm terminal` for VMs)
- **Public Key Authentication** — Both admin and client access is controlled via SSH public keys
- **Auto-Discovery** — Periodically discovers containers and VMs from configured Proxmox hosts via `pct list` / `qm list`
- **Admin TUI** — Full Bubble Tea interactive console for managing instances, clients, groups, access rules, and admin keys
- **Access Control** — Per-client and per-group access rules with a global default policy fallback
- **SQLite Storage** — Single-file embedded database, no external dependencies

## Quick Start

```bash
# Build
mise run build

# Run with a flag-based admin key (active as long as the flag is set)
./proxpass --admin-key "$(cat ~/.ssh/id_ed25519.pub)"

# Connect as admin (any SSH username works, identity is key-based)
ssh -p 2222 admin@localhost
```

Once connected to the TUI, add your public key as a persistent admin key in the database. After that the `--admin-key` flag is no longer required (but can be kept as a fallback).

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

The `--admin-key` flag accepts an SSH public key in `authorized_keys` format. When set, this key is treated as an admin key **for the lifetime of the process**, checked before any database lookup. This serves two purposes:

1. **Initial setup** — On a fresh database with no admin keys, this is the only way to connect and reach the TUI to persist keys.
2. **Permanent override** — The key remains active as long as the flag (or `PROXPASS_ADMIN_KEY` env var) is present. Removing the flag revokes this access immediately.

Users are identified solely by their public key — the SSH username is not used for authentication.

```bash
# Via flag
./proxpass --admin-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."

# Via environment variable
export PROXPASS_ADMIN_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
./proxpass
```

## How It Works

1. **Admin** connects via SSH with a recognized admin key → gets the Bubble Tea TUI
2. **Admin** adds Proxmox instances (hostname + SSH key path) via the TUI
3. **Discovery** periodically SSHes into each Proxmox host and runs `pct list` / `qm list`
4. **Admin** adds clients (name + public key) and grants them access to specific guests
5. **Client** connects via SSH using the guest name as the username: `ssh -p 2222 mycontainer@proxy-host`
6. **Proxy** authenticates the client by key, checks access rules, then proxies the session to the Proxmox host

## Architecture

```
proxpass/
├── cmd/proxpass/          # CLI entry point (urfave/cli v3)
└── internal/
    ├── models/            # Data types
    ├── db/                # SQLite repository
    ├── proxmox/           # Proxmox SSH client & discovery
    ├── ssh/               # SSH server, auth, proxy
    └── tui/               # Bubble Tea admin interface
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

# Snapshot release (local only)
mise run release

# Clean build artifacts
mise run clean
```
