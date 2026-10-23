# ProxPass

**An SSH gateway for Proxmox VE.** ProxPass lets people reach your Proxmox
containers and virtual machines over plain `ssh`, without giving anyone a
Proxmox login or a shell on the host — you decide who may reach which guest,
and they connect straight to its console.

It ships as a single Docker image and is managed from a **browser admin UI**
(or, if you prefer, over SSH). Storage is one embedded SQLite file; there are
no external dependencies to run.

## What you get

- **Real OpenSSH.** Clients connect with `ssh`, authenticated by public key.
- **Connect by name or ID.** `ssh webserver@proxpass`, `ssh ct100@proxpass`, or
  pick from an interactive list.
- **Run commands in a guest.** `ssh ct100@proxpass whoami` runs inside the
  container, with streams, exit status and PTY behaving like any other ssh.
- **Access control.** Grant individual clients or groups access to specific
  guests (or whole nodes), with a default policy for everything else.
- **Auto-discovery.** The guest list stays in sync with your Proxmox hosts.
- **Admin web UI + REST API.** Manage everything from the browser; a typed
  `/v1` API is there too.

## How it works

```
ssh alice@proxpass ct100
        │
        ▼
     sshd ── proxpass decides who alice is and where she lands
        │
        ▼
     Proxmox guest console
```

sshd owns the SSH protocol; proxpass supplies the users, the keys and the
session, and connects the client to the chosen guest's console. See
[doc/architecture.md](doc/architecture.md) for the full picture.

## Quick start

### 1. Run proxpass

```bash
docker run -d --name proxpass \
  -p 2222:22 \
  -p 8080:8080 \
  -v proxpass-data:/var/lib/proxpass \
  -e PROXPASS_ADMIN_KEY="$(cat ~/.ssh/id_ed25519.pub)" \
  -e PROXPASS_LISTEN="0.0.0.0:8080" \
  -e PROXPASS_REST_API_TOKEN="$(openssl rand -hex 32)" \
  ghcr.io/eun/proxpass:latest
```

- `PROXPASS_ADMIN_KEY` is **your** SSH public key — it identifies you as the
  administrator.
- `PROXPASS_REST_API_TOKEN` is the password for the web UI. Pick a long random
  value (`openssl rand -hex 32`) and keep it secret: anyone with it has full
  admin access. Note the one you generated above.
- `PROXPASS_LISTEN=0.0.0.0:8080` plus `-p 8080:8080` publish the web UI; the
  `-p 2222:22` publishes SSH for clients.

> If it is reachable beyond localhost, put the web UI behind TLS.

### 2. Open the web UI and sign in

Browse to **`http://localhost:8080/`** and sign in with the
`PROXPASS_REST_API_TOKEN` value from step 1.

### 3. Add your Proxmox node

In the UI, go to **Proxmox Nodes → New** and fill in:

- the **API URL** (e.g. `https://pve:8006`),
- an **API token ID** and **secret** — create one in Proxmox under
  *Datacenter → Permissions → API Tokens*. Uncheck **Privilege Separation**
  so the token inherits the user's permissions; otherwise it has no rights of
  its own and proxpass cannot list guests or open consoles.

The node must be reachable: proxpass calls the API to learn the node name and
to list guests. Once added, proxpass discovers the running guests and keeps the
list in sync.

> **Self-signed certificate?** Proxmox's stock certificate is self-signed, so
> tick **Skip TLS verification** on the form (or present a certificate your
> host trusts).

### 4. Add clients and grant access

- **Clients → New**: give the person a name and paste their SSH **public key(s)**.
  Optionally put them in a **Group**.
- **Guest Access** (or **Node Access**): grant that client or group access to
  the specific guests (or nodes) they should reach. The **Default Policy** page
  sets what everyone may reach when no explicit rule applies.

### 5. Connect

Your client connects over SSH. With no guest named, proxpass opens an
interactive picker; naming a guest connects straight to it:

```bash
ssh -p 2222 you@proxpass                 # pick from a list
ssh -p 2222 webserver@proxpass           # by guest name
ssh -p 2222 ct100@proxpass               # by type + VMID
ssh -p 2222 ct100@proxpass whoami        # run a command inside the guest
```

> **The login name is the guest, not who you are.** Your key identifies you;
> the login name only says where to land.

## Managing proxpass over SSH

The web UI is the easy path, but everything it does is also available from a
**command-line interface delivered over SSH** — handy for scripting, automation,
or running without exposing an HTTP port. Log in as the reserved `admin` user
with your admin key:

```bash
ssh -p 2222 admin@localhost                 # interactive, or:
ssh -p 2222 admin@localhost instance ls     # run a single admin command
ssh -p 2222 admin@localhost client add --name alice --key "ssh-ed25519 AAAA… alice"
ssh -p 2222 admin@localhost access grant --client alice --guest 100
```

See **[doc/admin-cli.md](doc/admin-cli.md)** for the full command reference and
the equivalent REST API.

## Documentation

- **[doc/web-ui.md](doc/web-ui.md)** — the admin web UI in depth (exposing it,
  logging in, how it is built).
- **[doc/admin-cli.md](doc/admin-cli.md)** — the SSH admin CLI and the `/v1`
  REST API.
- **[doc/client-connections.md](doc/client-connections.md)** — how clients
  connect: guest resolution, running commands, the login-name rules.
- **[doc/guest-console.md](doc/guest-console.md)** — the interactive picker,
  the status bar, resizing and leaving a console.
- **[doc/configuration.md](doc/configuration.md)** — every environment
  variable, the database, the Proxmox SSH key, host-key verification, file
  transfer, and identity resolution.
- **[doc/architecture.md](doc/architecture.md)** — how the pieces fit together,
  guest naming, and access control (rules and the default policy).
- **[doc/development.md](doc/development.md)** — building, testing and
  releasing.
