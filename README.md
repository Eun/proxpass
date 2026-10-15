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
- **Run Commands In Guests** — `ssh ct100@host whoami` runs it inside the container, with the exit status, streams and PTY behaving as any other ssh
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

**1. Run proxpass.** The admin key is your own public key: it is what lets you
run the CLI in the steps below.

```bash
docker run -d --name proxpass \
  -p 2222:22 \
  -v proxpass-data:/var/lib/proxpass \
  -e PROXPASS_ADMIN_KEY="$(cat ~/.ssh/id_ed25519.pub)" \
  ghcr.io/eun/proxpass:latest
```

**2. Add a Proxmox instance.** Nothing is discovered until proxpass knows where
to look, so this has to come before you connect.

```bash
ssh -p 2222 admin@localhost instance add \
  --url https://pve:8006 \
  --token-id "user@pam!token" \
  --token-secret "uuid"
```

The Proxmox host must be reachable now: `instance add` calls the API to learn
the node name, and fails if it cannot. Consoles use the termproxy WebSocket by
default — add `--console-transport ssh` to use `pct enter` / `qm terminal`
instead. Discovery then fills in the guest list; `ssh -p 2222 admin@localhost
guest ls` shows it.

Consoles work at this point. [File transfer](#file-transfer-with-scp-and-sftp)
additionally needs the [proxpass SSH key](#the-proxmox-ssh-key) installed on
the node. On a default termproxy instance nothing checks that for you, so
install it now rather than discovering it at your first `scp`.

**3. Connect and pick a guest.** With no command, proxpass opens the
[picker](#the-guest-picker):

```bash
ssh -p 2222 admin@localhost
```

**4. Connect straight to a guest** by putting its identifier in the login name:

```bash
ssh -p 2222 ct100@localhost          # type + VMID
ssh -p 2222 100@localhost            # VMID alone
ssh -p 2222 webserver@localhost      # guest name
ssh -p 2222 ct101@pve1@localhost     # instance-qualified, when a name is ambiguous
```

> **The login name is the guest you want, not who you are.** Your key
> identifies you; the login name only says where to land. So use **`admin`**
> for the CLI and the picker — it is the one reserved name, and always
> browses even if a guest happens to share it. Every other name, including
> your own, is resolved as a guest first, which means `ssh myguest@localhost
> guest ls` runs `guest ls` *inside that guest* rather than in proxpass.

## The picker

Connecting without a command opens an interactive picker over everything you
may reach — guests and Proxmox nodes together:

```
proxpass — available to admin

  ID     NAME ▲            STATUS   HOST
▸ node   pve1              -        pve1
  ct103  merge-with-label  running  pve1
  ct126  mautrix-telegram  running  pve1
  ct118  mautrix-whatsapp  running  pve2

  51 targets · sort: name
  ↑/↓ move · type to filter · ⏎ connect · tab sort · esc clear · ctrl+c quit
```

A node is the row with `node` in the `ID` column; selecting it opens a shell
on the Proxmox host, exactly as `ssh <node>@proxpass` would. Nodes you have
not been granted are not listed, and neither is one with no `--ssh-host`,
since it could not be opened.

Typing filters the list as a fuzzy subsequence match, so `mw` finds
`mautrix-whatsapp` and `118` finds `ct118`. Each of the name, the type+VMID
and the host is matched on its own, and a hit on the name ranks highest —
and because `node` is matched as a node row's id, typing it narrows the list
to the nodes.

### Sorting

**`Tab`** cycles the sort column and **`Shift+Tab`** goes back. The `▲` in
the header marks the active column and the status line names it:

| Column | Order |
| --- | --- |
| `ID` | numeric by VMID, so `ct99` comes before `ct118`; nodes group at the top, having no VMID |
| `NAME` | alphabetical |
| `STATUS` | running first, since those are the ones you can enter; a node ranks with them, being always connectable |
| `HOST` | alphabetical by Proxmox host; a node sorts with the guests that live on it |

`Tab` walks those in the order the header prints them, left to right. The
picker **opens** sorted by `NAME`, which is what you want when scanning a
list of guests, and the first `Tab` starts the walk at `ID` rather than
continuing from where the list happens to rest:

```
name (open) → id → name → status → host → id → ...
```

`Shift+Tab` is the exact inverse, and from a freshly opened picker it starts
at the other end of the cycle, `HOST`.

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

Taking the row back is the delicate half. Leaving the alternate screen
restores the normal screen's cursor along with its scroll region — that
restore is what returns you to the prompt you ran `vim` from — so the bar has
to reinstate its region without disturbing the position the terminal just put
back. It does that the same way it does on a resize: `DECSC`/`DECRC` around
the `DECSTBM`, in one write.

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

### Resizing

A resize is one of the moments the bar has to touch the guest's cursor,
because `DECSTBM` **moves it**. DEC's own specification requires that — the
VT100 User Guide says of `DECSTBM` "the cursor is placed in the home position", and
the VT510 manual is blunter: "DECSTBM moves the cursor to column 1, line 1 of
the page." Every terminal checked implements it (xterm, VTE, alacritty, kitty,
foot, wezterm, st, Windows Terminal, tmux, GNU screen, iTerm2); none leaves
the cursor alone.

Reinstalling the region after a resize is mandatory rather than tidying up:
terminals discard the scroll region when the window changes size — xterm's
`ScreenResize` calls `resetMargins`, VTE's `set_size` calls
`reset_scrolling_region` — so until proxpass reinstalls it, the bar's row is
not reserved at all. The reinstall is therefore unavoidable, it homes the
cursor, and the bar has to put the cursor back. It does that by bracketing the
region change with `DECSC`/`DECRC` in a single write, skipping the save when
the guest is already holding the slot.

This matters most on a **VM serial console**. A container console is a PTY, so
a resize reaches the guest as `SIGWINCH` and the shell redraws, which hides a
misplaced cursor. A VM serial console is an emulated UART with no window-size
concept: neither transport can deliver the new size, and the guest's geometry
stays frozen for the session. Nothing redraws, so anything done to the cursor
there is permanent — which is why resize bugs showed up on VMs first. If a VM
guest's idea of the screen size matters to you, run `resize` or
`stty rows … cols …` inside it; that is the only way it can learn.

A terminal dragged below four rows gives the row back rather than keeping a
reservation it is too small for, and takes it again when the window grows.

One case is left deliberately unfixed. `DECRC` clamps to the screen rather
than to the scroll region, so a window shrunk past the guest's cursor leaves
that cursor on the bar's row, where the guest writes over the bar until it
positions itself again — a shell does that at its next prompt. The bar keeps
repainting throughout, so it is never lost. Correcting it properly would mean
parsing the guest's output to track the cursor, which is the design this bar
exists to avoid; the previous behavior traded this rare case for moving the
cursor on *every* resize, which was the bug.

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

# Add a single instance (termproxy console — the default)
ssh -p 2222 admin@proxpass instance add \
  --url https://pve:8006 \
  --token-id "user@pam!token" \
  --token-secret "uuid"

# Attach consoles over SSH (pct enter) instead of the termproxy websocket.
# No key flag: proxpass uses its own key (see "The Proxmox SSH key" below).
# --ssh-host is optional: when omitted the hostname from --url is used (pve, port 22).
# An explicit --ssh-host may include a port: --ssh-host pve:2222
ssh -p 2222 admin@proxpass instance add \
  --url https://pve:8006 \
  --token-id "user@pam!token" \
  --token-secret "uuid" \
  --console-transport ssh

# Override the SSH host/port explicitly (single --url only)
ssh -p 2222 admin@proxpass instance add \
  --name pve1 \
  --url https://pve1:8006 \
  --token-id "user@pam!token" \
  --token-secret "uuid" \
  --console-transport ssh \
  --ssh-host pve1.internal:2222

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
  --console-transport ssh

# Change an existing instance. Only the flags you pass are changed, and the
# instance keeps its id -- so its access rules survive, which re-adding it
# would not.
ssh -p 2222 admin@proxpass instance update --name pve1 --ssh-host pve1.internal:2222
ssh -p 2222 admin@proxpass instance update --name pve1 --token-id "user@pam!new" --token-secret "uuid"
ssh -p 2222 admin@proxpass instance update --name pve1 --rename pve-old

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

# Grant a shell on the Proxmox node itself, rather than on a guest.
# Both kinds may be granted in one command.
ssh -p 2222 admin@proxpass access grant \
  --client alice --instance pve1
ssh -p 2222 admin@proxpass access grant \
  --client alice --guest webserver --instance pve1
ssh -p 2222 admin@proxpass access revoke \
  --client alice --instance pve1

# Manage default policy — guests only; see "Granting a node" below
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
| `--data` | `PROXPASS_DATA` | `/var/lib/proxpass/proxpass.db` | SQLite file path, or a `postgres://` URL (see below) |
| `--log-level` | `PROXPASS_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `--admin-key` | `PROXPASS_ADMIN_KEY` | | Admin public key (see below) |
| `--public-endpoint` | `PROXPASS_PUBLIC_ENDPOINT` | | Hostname clients connect to, shown in the status bar (see below) |
| `--listen` | `PROXPASS_LISTEN` | `127.0.0.1:8080` | Address of the NSS directory API (`serve` only) |
| `--discovery-interval` | `PROXPASS_DISCOVERY_INTERVAL` | `5m` | Guest discovery poll interval (`serve` only) |

The SSH port itself is sshd's, so it is published with `-p` on the container
rather than configured in proxpass.

### Database

proxpass stores its state in SQLite by default: one file, nothing to run, and
the right answer for a single deployment.

Point `--data` at a `postgres://` URL to use PostgreSQL instead:

```yaml
environment:
  PROXPASS_DATA: "postgres://proxpass:secret@db:5432/proxpass?sslmode=disable"
```

The backend is inferred from the value — a `postgres://` or `postgresql://`
URL selects PostgreSQL, anything else is a SQLite path — so there is one
setting to get right rather than two that can disagree. The schema is created
on first start, as it is for SQLite.

There is no migration path between the two: switching backend starts from an
empty database. If you have an existing SQLite deployment, recreate your
instances and clients against the new database rather than expecting the data
to follow.

Worth knowing before choosing PostgreSQL: with SQLite, write access is
enforced by the file's group permissions, so a client session cannot modify
the database whatever the application does. With PostgreSQL that containment
is gone — access is whatever the DSN's credentials allow. Give proxpass a role
scoped to its own database.

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

### The Proxmox SSH key

proxpass reaches a Proxmox node over SSH for two things: attaching a console
when `--console-transport ssh` is set, and **file transfer, which always uses
it** whatever the console transport. proxpass owns the key: the container
entrypoint generates an ed25519 keypair on the volume at first start, and
`instance add` no longer takes a key at all.

**One key for the whole deployment**, not one per instance. Its public half
has to be installed on each Proxmox host by hand — a key per instance would
multiply that work without isolating anything, since whoever can read one can
read them all.

Read the public half to install it:

```bash
docker compose exec proxpass cat /var/lib/proxpass/ssh/proxpass_key.pub
```

and append it to `~/.ssh/authorized_keys` for the user named by `--ssh-user`
(`root` by default) on each Proxmox host. On a **clustered** node that file is
a symlink into `/etc/pve/priv/authorized_keys`, which pmxcfs replicates, so
installing it once per *cluster* covers every node in it. A standalone node
needs its own copy. Proxmox only ever appends to and de-duplicates that file,
so the key is not removed by `pvecm updatecerts` or by a node join.

`instance add` checks that the key opens the host and prints it if not:

```
Warning: pve1 is not reachable over SSH yet: authenticating as root: ...
Add this key to ~/.ssh/authorized_keys on pve1, then run `instance inspect pve1' to re-check:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... proxpass
```

The warning is **not** fatal and the instance is still added — you cannot
install the key before there is an instance telling you which host to install
it on. `instance inspect` re-runs the check, so it is the way to confirm the
key landed.

The key lives on the volume rather than in the database, so recreating the
container does not invalidate what you have already installed, and so a
Proxmox credential stays out of a table an admin session can read through
`/admin/rpc`. `PROXPASS_SSH_KEY_FILE` points at a different file for a
deployment that manages its own key; nothing is generated when that file
already exists.

> **Upgrading:** instances added before this could carry their own key, and
> the migration that removes the columns **discards it**. Such an instance
> falls back to the deployment key, so install that key's public half on its
> Proxmox host before upgrading, or the instance stops connecting until you
> do. `instance inspect` reports exactly that, and the host's existing
> `authorized_keys` entry for the old key can be removed afterwards.

### File transfer with scp and sftp

> **Prerequisite: install the proxpass SSH key on the Proxmox node first.**
> SFTP and `scp` reach a container *through* its node, and reach a node
> directly, so neither works until proxpass can log in to that node — regardless of
> `--console-transport`, and even for an instance whose consoles work fine
> over termproxy. Append the key's public half to `~/.ssh/authorized_keys` for
> the user in `--ssh-user` (`root` by default) on each node; see
> [The Proxmox SSH key](#the-proxmox-ssh-key) for how to read it.
>
> Only an `ssh` instance tells you when the key is missing: `instance add`
> warns, and `instance inspect` re-checks. A **termproxy** instance reports
> neither, because both are console checks — so there the first sign is a
> transfer failing. Installing the key is what fixes it either way.

Files can be copied into and out of a **container** or a **node** by naming
it as the login name:

```bash
# a container
scp ./app.tar.gz ct100@proxpass:/opt/
scp ct100@proxpass:/var/log/syslog ./
scp -r ./site ct100@proxpass:/var/www/
sftp ct100@proxpass

# a Proxmox node
scp ./backup.sh pve1@proxpass:/root/
sftp pve1@proxpass
```

The same resolution as `ssh <name>@proxpass` applies, including the
instance-qualified `ct100@rome` form and the rule that **a node wins a name
collision**, and it is scoped to what your key already reaches — naming a
target grants nothing.

The two work quite differently underneath:

| | How it works |
|---|---|
| **Container** | Runs **inside the container's namespaces**, so a path means what it means in the container: a symlink there cannot point at a file on the node. Nothing is staged on the node; the bytes stream straight through. |
| **Node** | proxpass asks the node's own sshd for its `sftp` subsystem and pumps bytes between it and your client. Paths are the node's, and the transfer is as capable as the node's `sftp-server` makes it. |

Limits worth knowing:

| Not supported | Why |
|---|---|
| Virtual machines | A VM has no namespace to enter. Reaching its disk means the guest agent, whose write endpoint truncates at 60 KiB and cannot append. |
| A node proxpass cannot log in to | Both paths reach the node over SSH, so the key above is what enables them. |
| A node with no `--ssh-host` | There is nowhere to connect; such an instance is not offered as a transfer target. |

Note that `--console-transport` is **not** one of these: it selects how a
*console* is attached and has nothing to do with file transfer. A termproxy
instance transfers files over SSH to the node just as an `ssh` one does.

A **container** also needs a shell and `cat`/`stat`/`dd` — BusyBox is enough,
so Alpine works. A distroless container cannot be served. A **node** needs
none of that: it needs its own `sftp` subsystem enabled, which every stock
Proxmox install has.

> **Why `scp` works without `-O`:** since OpenSSH 9.0 `scp` speaks the SFTP
> protocol by default and does *not* fall back to the legacy one, so serving
> SFTP is what makes a plain `scp` work. Both commands are the same protocol
> here.

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

> **The login name decides where a command runs.** `ssh ct100@host whoami`
> runs `whoami` *inside* ct100, because the login name addresses that
> container. proxpass's own CLI stays reachable under any name that is not a
> guest, and under `admin` whatever happens — so `ssh admin@host guest ls` is
> always the CLI. `admin` is the only name reserved that way: if a guest is
> called `alice`, then `ssh alice@host guest ls` runs in *that guest*.

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

# Run a command IN the guest, like any other ssh
ssh -p 2222 ct100@proxpass-host whoami
ssh -p 2222 ct100@proxpass-host cat /etc/os-release
ssh -t -p 2222 ct100@proxpass-host top     # -t for anything interactive

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
- **`admin` always means "browse".** It opens the picker even if a guest
  shares the name, since guest names come from Proxmox and proxpass does not
  control them — so there is always a way back to the list. It is the only
  reserved name: a client called `web` does not stop `ssh web@host` from
  reaching the container called `web`. That costs the client nothing,
  because the login name is not a credential — identity comes from the key,
  so she can browse under `admin` and still be herself.
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

## Names

Clients, groups and instances are referred to by name, and **names are
matched without regard to case**: an instance added as `rome` is reached as
`ROME@proxpass`, removed with `instance rm Rome`, and granted with
`access grant --instance RoMe`.

**Names are stored in lower case.** Whatever you type is folded when it is
written, so `instance add --name ROME` creates `rome`, and that is the
spelling `instance ls` shows, the session log records, and the picker
displays. Case is a convenience when typing a name, not something proxpass
remembers about it.

Uniqueness follows from the same rule, so `alice` and `Alice` cannot both be
clients. That is what makes the matching above answerable: with both present
there would be no single client the name refers to, and the one you got
would depend on row order.

> **Upgrading:** names written by an older version are folded automatically
> when the database is opened, so `Alice` becomes `alice` with its keys,
> memberships and access rules intact — those are held by row id, which does
> not change.
>
> The one case that cannot be handled automatically is a database that
> already contains *both* spellings. They cannot both become `alice`, so
> proxpass refuses to start rather than guess, naming the pair:
>
> ```
> names must be unique ignoring case, and these are not:
>   client names "Alice" and "alice" differ only by case (all are "alice")
> ```
>
> Rename or remove one of each pair with the previous version, then upgrade.
> They are not merged: each may have its own keys, memberships and access
> rules, and there is no way to know which was meant.

The one exception is `admin`, which is reserved in any case — `ADMIN`,
`Admin` and `admin` all mean the administrator's login, and no client may
be created with that name.

## Access Control

Access to a **guest** is checked in order:

1. **Explicit client rule** — client is directly granted access to the guest
2. **Group rule** — client belongs to a group that is granted access to the guest
3. **Default policy** — client or their group is listed in the global default policy

### Granting a node

`access grant --instance <name>` grants a shell on the Proxmox node itself,
to be reached as `<instance-name>@proxpass`. It is checked the same way,
**minus the third step**: a node is reachable only when a client or group
rule says so by name.

```bash
ssh pve1@proxpass            # a shell on the node
ssh pve1@proxpass uptime     # one command on it
```

The shell is whatever login shell the configured `--ssh-user` has. A node is
reached **only over SSH**, whatever `--console-transport` says: that setting
decides how a *guest* console attaches and has no bearing on the node, so an
instance with no `--ssh-host` cannot be opened as one.

> **Name collisions: the node wins.** If an instance and a guest share a
> name, `ssh rome@proxpass` reaches the **node**. The guest is still
> reachable as `ssh rome@rome@proxpass` — `<guest>@<instance>` — whereas a
> node has no such qualified form, so resolving the guest first would make
> the node unreachable altogether. Nothing becomes unreachable this way.
>
> `admin` remains reserved: an instance called `admin` does not take the
> administrator's login or CLI.

`scp` and `sftp` reach a node too — see
[File transfer](#file-transfer-with-scp-and-sftp).

The default policy is left out deliberately. It has no notion of a target —
a client listed there reaches *anything* — and it is standing configuration,
often set once and forgotten. An administrator who ran `policy add --client
alice` before this existed was saying something about guests, because guests
were the only thing it could mean; reading it now as consent to a root shell
on every node would be putting words in their mouth.

Node and guest grants are **independent**. Granting a node does not grant its
guests, and granting every guest does not grant the node:

```bash
# alice may enter the node, and two containers on it. Nothing else.
access grant --client alice --instance pve1 --guest ct100 --guest ct101
```

What that buys inside the node is not proxpass's business: a shell there can
reach the containers by other means, and is expected to. The rules say who
proxpass lets in, not what they can do once inside.

`access ls` shows both, with a `KIND` column saying which is which — worth
having, since a node and a guest may share a name:

```
TYPE     SUBJECT              KIND     TARGET
client   alice                guest    webserver (ct100)
client   alice                node     pve1
```

`--json` returns them under separate `guests` and `instances` keys, so a
consumer that predates node rules keeps reading `guests` unchanged.

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
