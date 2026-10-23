# Architecture

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
[File transfer](configuration.md#file-transfer-with-scp-and-sftp).

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

