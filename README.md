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
go build -o proxpass ./cmd/proxpass/

# Run (generates host key on first start)
./proxpass --listen :2222 --data ./proxpass.db

# Connect as admin (after adding your key as admin key)
ssh -p 2222 admin@localhost
```

## Configuration

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--listen` | `PROXPASS_LISTEN` | `:2222` | SSH listen address |
| `--host-key` | `PROXPASS_HOST_KEY` | `./proxpass_host_key` | Path to ED25519 host key |
| `--data` | `PROXPASS_DATA` | `./proxpass.db` | Path to SQLite database |
| `--discovery-interval` | `PROXPASS_DISCOVERY_INTERVAL` | `5m` | Guest discovery poll interval |
| `--log-level` | `PROXPASS_LOG_LEVEL` | `info` | Log level |

## How It Works

1. **Admin** connects via SSH with a registered admin key → gets the Bubble Tea TUI
2. **Admin** adds Proxmox instances (hostname + SSH key path) via the TUI
3. **Discovery** periodically SSHes into each Proxmox host and runs `pct list` / `qm list`
4. **Admin** adds clients (name + public key) and grants them access to specific guests
5. **Client** connects via SSH using the guest name as the username: `ssh -p 2222 mycontainer@proxy-host`
6. **Proxy** authenticates the client by key, checks access rules, then proxies the session to the Proxmox host

## Architecture

```
proxpass/
├── cmd/proxpass/          # CLI entry point
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
# Run tests
go test ./... -v

# Build and vet
go build ./...
go vet ./...
```
