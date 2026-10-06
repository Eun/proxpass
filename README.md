# ProxPass

An SSH proxy for Proxmox VE that routes client connections to LXC containers and QEMU virtual machines. Administrators manage access through a CLI delivered over SSH.

ProxPass ships as a single Docker image containing OpenSSH `sshd` and the
proxpass binary. It does **not** implement its own SSH server: sshd owns the
protocol, and proxpass supplies the users, the keys and the session.

## Features

- **Real OpenSSH** — sshd handles the protocol; proxpass only decides who may log in and where they land
- **Public Key Authentication** — The only supported method; password authentication is disabled
- **Auto-Discovery** — Periodically reconciles the guest list against the configured Proxmox hosts via the REST API: guests that start are added, and guests that stop or are destroyed are removed
- **Admin CLI over SSH** — Full command-line interface for managing instances, clients, groups, access rules, and admin keys
- **Flexible Guest Resolution** — Connect by VMID (`100`), type+VMID (`ct100`), name (`webserver`), or instance-qualified (`ct101@rome`) — as the login name (`ssh ct100@host`) or via `guest connect`
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

# Connect as admin and pick a guest interactively.
# Any login name works with an admin key; "admin" is just the canonical one.
ssh -p 2222 admin@localhost
```

## The guest picker

Connecting without a command opens an interactive picker:

```
proxpass — guests available to admin

  ID     NAME ▲            STATUS   HOST
▸ ct103  merge-with-label  running  pve1
  ct126  mautrix-telegram  running  pve1
  ct118  mautrix-whatsapp  running  pve2

  50 guests · sort: name
  ↑/↓ move · type to filter · ⏎ connect · tab sort · esc clear · ctrl+c quit
```

Typing filters the list as a fuzzy subsequence match, so `mw` finds
`mautrix-whatsapp` and `118` finds `ct118`. Each of the name, the type+VMID
and the host is matched on its own, and a hit on the name ranks highest.

### Sorting

**`Tab`** cycles the sort column and **`Shift+Tab`** goes back. The `▲` in
the header marks the active column and the status line names it:

| Column | Order |
| --- | --- |
| `NAME` | alphabetical (the default) |
| `ID` | numeric by VMID, so `ct99` comes before `ct118` |
| `STATUS` | running first, since those are the ones you can enter |
| `HOST` | alphabetical by Proxmox host |

Tab is used rather than a letter because every printable key goes into the
filter — binding `s` would make it impossible to type a guest called
`staging`.

While a filter is active the list stays ordered by **match relevance**, which
is the point of filtering, and the status line says `sort: best match`.
Pressing `Tab` then still records your choice and applies it as soon as you
clear the filter.

Without a PTY — `ssh host` with input redirected, for instance — the picker
falls back to a plain numbered prompt so scripted use keeps working. That
table shows the same four columns but has no hotkeys.

## The status bar

While you are attached to a guest console, the bottom row shows which guest
you are on and how to leave it:

```
 webserver@pve1 (ct100)                        Ctrl+A X: disconnect
```

The name reads as the login form that reaches the same guest: the guest, then
the instance it runs on. Set [`--public-endpoint`](#public-endpoint) and the
hostname your users connect to is appended, so a session names itself in full:

```
 webserver@pve1@proxpass.example.com (ct100)   Ctrl+A X: disconnect
```

proxpass reserves that row with a **scroll region** (`DECSTBM`) and asks the
guest for a PTY one row shorter, so the terminal scrolls the guest's output
natively and never touches the bar. Guest output is forwarded verbatim —
proxpass does not re-render it — and the bar itself is repainted only when
its text changes, at most once per 50 ms.

That matters because of how this used to work: the previous implementation
parsed all guest output through a VT100 emulator and redrew the whole screen
on every write, which measured **26 MB/s** and made watching logs unusable.
The current approach measures **~5 GB/s**, roughly 190× faster, so there is
no longer a throughput reason to turn it off.

When a full-screen application takes over — vim, top, less — the bar detects
the switch to the alternate screen, releases the scroll region and stops
drawing, so the application gets the whole terminal. It comes back when the
application exits.

It also stands aside for a guest that takes the screen's geometry for itself.
An application setting its own scroll region replaces the bar's reservation,
so the bar reinstates it; one setting origin mode (DECOM) makes the bar's row
unaddressable, so the bar stops drawing until the mode is cleared rather than
painting over the guest's bottom line.

The bar also stands aside when the guest saves its cursor. A terminal has only
one slot to save a cursor position in, and terminfo's `sc`/`rc` capabilities
are exactly the sequences the bar uses, so a shell redrawing its line — which
is what an arrow key or Home/End causes — is competing for the same slot. The
bar notices the save and skips its repaint until the guest restores, rather
than overwriting the position the guest is about to return to. An unmatched
save releases the bar after a second, so a guest that saves and never restores
costs a late bar rather than a missing one.

Set `PROXPASS_DISABLE_STATUSBAR=1` to turn the bar off; the guest then gets
the full terminal height. The bar also disables itself without a PTY or on a
terminal shorter than four rows.

It is read from the **session's** environment, and sshd builds that from
scratch rather than inheriting the container's, so it has to be sent with the
connection:

```bash
ssh -o SetEnv=PROXPASS_DISABLE_STATUSBAR=1 -p 2222 admin@proxpass-host
```

Or once, in `~/.ssh/config`:

```
Host proxpass-host
    SetEnv PROXPASS_DISABLE_STATUSBAR=1
```

Setting it on the container (`docker run -e …`) has no effect, because sshd
does not pass its own environment to a session. The image's sshd config
accepts this one variable by name; it deliberately does not accept
`PROXPASS_*` as a pattern, since `PROXPASS_ADMIN_KEY` and `PROXPASS_DATA`
also configure the session binary.

## Leaving a guest console

Normally you leave a console the way you would any shell: `exit`, `logout`,
or `Ctrl+D`. When that is not possible — a wedged process, a full-screen
application that has swallowed your keys — press **`Ctrl+A X`** to disconnect.
The sequence is handled by proxpass rather than the guest, so it works even
when the guest has stopped responding. The status bar shows the reminder; when
there is no bar, proxpass prints it once as you connect.

Note that `Ctrl+A` is also start-of-line in most shells and the default
prefix for `screen` and `tmux`. A lone `Ctrl+A` is passed through to the
guest unchanged, so only the two-key sequence disconnects, but if you run
`screen` or `tmux` inside a guest you will be nesting prefixes.

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
| `--public-endpoint` | `PROXPASS_PUBLIC_ENDPOINT` | | Hostname clients connect to, shown in the status bar (see below) |
| `--listen` | `PROXPASS_LISTEN` | `127.0.0.1:8080` | Address of the NSS directory API (`serve` only) |
| `--discovery-interval` | `PROXPASS_DISCOVERY_INTERVAL` | `5m` | Guest discovery poll interval (`serve` only) |

The SSH port itself is sshd's, so it is published with `-p` on the container
rather than configured in proxpass.

### Public endpoint

`--public-endpoint` is the hostname your users put in `ssh`. proxpass cannot
work this out for itself: the name clients use is a DNS and port-forwarding
fact that never reaches the server, which only ever sees its own container.

When it is set, the status bar names the guest the way you would reach it:

```
container1@rome@proxpass.example.com (ct100)
```

which is the `ssh ct100@rome@host` form read left to right — the guest, the
instance it runs on, and the endpoint you came in through. Without it the
endpoint is simply left out:

```
container1@rome (ct100)
```

Like the admin key, the value is persisted to the database when `serve`
starts, because sshd gives each session a fresh environment and the variable
would otherwise be invisible to it. Unlike the admin key it is *replaced* on
every start, so changing it in your compose file and restarting is enough —
and clearing it removes it, rather than leaving a stale hostname on screen.

### Admin key

`--admin-key` accepts a single SSH public key in `authorized_keys` format and
authorizes the administrator.

An admin key works under **any login name**, because the key is what grants
admin — the name is a label, not a credential. Equally, a client's key never
grants admin, even under the name `admin`:

```bash
ssh -p 2222 admin@proxpass guest ls     # the canonical name
ssh -p 2222 tobias@proxpass guest ls    # equivalent: authorized by the key
```

Because the name is served over NSS rather than written to `/etc/passwd`,
it is not bound by `useradd` policy: mixed case, a leading digit, dots and
non-ASCII all work, so `Tobias`, `1st-box` and `tobías` are all valid. The
only names refused are the ones that would not survive the lookup — a name
longer than 256 characters, or one containing `:`, a newline, `/`, `%`, `?`,
`#`, a space, or starting with `-`.

Because such a name is only a label, the UI names the identity the key
resolves to rather than echoing it back: logging in as `tobias@` with an
admin key shows `guests available to admin`. The login name as typed is what
gets logged, so the log still records what actually came in.

### How identity is decided

sshd is configured with `ExposeAuthInfo yes`, which tells the session which
key authenticated it. proxpass matches that key against the admin keys and
every client's keys:

| Outcome | Result |
|---|---|
| matches one admin key | administrator |
| matches one client | that client |
| matches nothing | **refused** |
| matches two identities | **refused** — a key must name exactly one |

This is why the login name can be anything: it never decides who you are. It
is also why `ExposeAuthInfo` is required rather than optional — with it off,
the session has only the name, so it refuses to start instead of guessing.

> **It is stored in the database on startup, not held in memory.** sshd runs
> `AuthorizedKeysCommand` with a scrubbed environment, so that process cannot
> see `PROXPASS_ADMIN_KEY`; persisting the key is what makes the admin able to
> log in at all. Consequently, **removing the flag or environment variable
> does not revoke access** — the key remains valid until it is removed
> explicitly:
>
> ```bash
> ssh -p 2222 admin@proxpass admin-key ls
> ssh -p 2222 admin@proxpass admin-key rm --key "ssh-ed25519 AAAA..."
> ```

### Users, groups and the database

Clients are served to NSS as users whose uid is derived from their database
id, all sharing the primary group `proxpass`. Administrator logins — `admin`
and any other non-client name — share one uid and the group
`proxpass-admin`.

The id layout is configurable, because the usable range is a property of the
deployment rather than of proxpass:

| Env Var | Default | Description |
|---------|---------|-------------|
| `PROXPASS_ADMIN_UID` | `19999` | uid of the `admin` login |
| `PROXPASS_ALIAS_UID` | `19998` | uid of a login name that names no configured account |
| `PROXPASS_ADMIN_GID` | `19001` | gid of `proxpass-admin`; the only group that may write the database |
| `PROXPASS_GID` | `19000` | gid of `proxpass`, every client's primary group (read-only) |
| `PROXPASS_UID_BASE` | `20000` | added to a client's row id to derive its uid |
| `PROXPASS_GID_BASE` | `40000` | added to a group's row id to derive its gid |
| `PROXPASS_MAX_ID` | `65535` | highest id proxpass will serve |

`PROXPASS_ALIAS_UID` must differ from `PROXPASS_ADMIN_UID`, and proxpass
refuses to start if it does not. An alias is reachable with *any* valid key,
including a client's, so an alias session must not share the administrator's
Unix identity — the gids already differ, and the uids do too.

> **Every id must stay below `PROXPASS_MAX_ID`, which defaults to 65535.** A
> user-namespaced Docker daemon (`userns-remap`, or rootless) maps only the
> 65536 subordinate ids from `/etc/subuid` into the container, so a higher id
> does not exist inside the namespace. sshd accepts the public key and *then*
> fails the login with:
>
> ```
> Accepted publickey for admin ...
> setresuid 99999: Invalid argument
> ```
>
> Raise `PROXPASS_MAX_ID` only if your daemon maps a wider range. The layout
> is validated at startup, so a bad combination refuses to boot with a
> message naming the offending variable instead of breaking logins later.

That split matters: `proxpass session` runs as the logged-in user, so it needs
filesystem access to the SQLite database. The database is owned by
`root:proxpass-admin` and mode `0664`, which means **the admin can write it
and clients can only read it**. A client session therefore cannot modify
another client's access rules, though it can read the database — which holds
the Proxmox API tokens. Treat any client login as able to read those
credentials, and rely on sshd's `ForceCommand` confinement (no shell, no
forwarding, no sftp) to keep that boundary.

Group membership is exposed as a *primary* group rather than a supplementary
one because supplementary groups require NSS enumeration, which has to stay
disabled: sshd's late `getgrent()` crashes the sshd child from inside the Go
runtime embedded in `libnss_http.so.2`.

### Subcommands

| Command | Invoked by | Purpose |
|---------|-----------|---------|
| `proxpass serve` | container entrypoint | Guest discovery + the NSS directory API |
| `proxpass authorized-keys <user>` | sshd `AuthorizedKeysCommand` | Prints the user's public keys |
| `proxpass session` | sshd `ForceCommand` | Runs the client's session |

## Client Connections

**Your key identifies you — the login name does not matter.** proxpass looks
up the key that authenticated and resolves it to a client (or to the
administrator); the name before the `@` is ignored. So all of these are the
same client:

```bash
ssh -p 2222 proxpass-host           # whatever your local username is
ssh -p 2222 alice@proxpass-host     # your client name
ssh -p 2222 anything@proxpass-host  # any name at all
```

A key that matches no client and no admin key is refused outright: proxpass
never falls back to trusting the name.

There are two ways to name a guest: as the **login name**, or through
**`guest connect`**. With neither you get the interactive picker.

```bash
# Interactive picker
ssh -p 2222 alice@proxpass-host

# As the login name (no -t needed)
ssh -p 2222 ct100@proxpass-host
ssh -p 2222 100@proxpass-host
ssh -p 2222 webserver@proxpass-host
ssh -p 2222 ct101@rome@proxpass-host     # instance-qualified

# Through the CLI (a PTY is required)
ssh -t -p 2222 alice@proxpass-host guest connect ct100
ssh -t -p 2222 alice@proxpass-host guest connect ct101@rome

# And to see what you may reach
ssh -p 2222 alice@proxpass-host guest ls
```

`guest ls` and `guest connect` are available to clients as well as
administrators, and both are scoped to the guests your key grants access to.

> **A bare guest identifier as the command — `ssh host ct100` — is no longer
> accepted.** A single token had to be guessed at (a guest, or a mistyped
> command?), and the guess was observable: `ssh host bogus` said "unknown
> command" while `ssh host ct999` reported a resolution failure. Use
> `guest connect ct100` or the login-name form.

### Guest name as the login name

A guest identifier also works as the **login name**, which is shorter to
type and needs no `-t`:

```bash
ssh -p 2222 ct100@proxpass-host        # same as: ssh -t … alice@host ct100
ssh -p 2222 100@proxpass-host
ssh -p 2222 webserver@proxpass-host
```

A name that matches no guest is just a login name, so `ssh admin@host` and
`ssh alice@host` still open the picker.

Three limitations follow from it being a login name rather than an argument:

- **Only guests you may already reach.** The name is resolved against the
  guests your key grants access to, so it is a shortcut, never a way in. A
  guest that exists but is not yours is treated exactly like one that does
  not exist — you get the picker, not an error — so the login name cannot be
  used to probe for machines.
- **Reserved names still mean "browse".** `admin` and any client name open
  the picker even if a guest happens to share that name, since guest names
  come from Proxmox and proxpass does not control them.
- **Instance-qualified names work here too.** `ssh ct101@rome@proxpass-host`
  selects ct101 on `rome`. ssh splits `user@host` on the last `@`, so the
  username arrives as `ct101@rome`; proxpass then splits that on its own
  last `@`, treating the suffix as an instance only when one really has
  that name. A guest whose name itself contains `@` therefore still works,
  and a client named `tobias@corp` is not mistaken for a qualified target.
- **Names longer than 256 characters** are rejected, as are names containing
  `/`, `%`, `?`, `#` or a space. Guests named that way remain reachable via
  the argument form and the picker.

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
