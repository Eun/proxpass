# Admin CLI and REST API

Everything the web UI does can also be driven from the SSH-delivered admin CLI or the typed `/v1` REST API.

## Admin CLI

The admin CLI is accessed over SSH. Commands are passed as the SSH exec command:

```bash
# List all commands
ssh -p 2222 admin@proxpass

# Manage Proxmox instances
ssh -p 2222 admin@proxpass instance ls

# Add a single instance (termproxy console — the default)
#
# Create the token in Proxmox under Datacenter → Permissions → API Tokens and
# UNCHECK "Privilege Separation" so it inherits the user's permissions —
# otherwise the token has no rights of its own and proxpass cannot list guests
# or open consoles.
#
# Note the SINGLE quotes around --token-id: a Proxmox API token id contains a
# "!" (e.g. user@pam!token), and inside double quotes an interactive bash
# triggers history expansion on it, mangling the value. Single quotes pass it
# through literally. The token secret is single-quoted for the same reason, in
# case it contains shell metacharacters.
ssh -p 2222 admin@proxpass instance add \
  --url https://pve:8006 \
  --token-id 'user@pam!token' \
  --token-secret 'uuid'

# A Proxmox host serving its stock self-signed certificate: TLS verification
# is ON by default, so either present a trusted certificate or add
# --insecure-tls (TLS and SSH each have their own toggle; --insecure sets both).
ssh -p 2222 admin@proxpass instance add \
  --url https://pve:8006 \
  --token-id 'user@pam!token' \
  --token-secret 'uuid' \
  --insecure-tls

# Attach consoles over SSH (pct enter) instead of the termproxy websocket.
# No key flag: proxpass uses its own key (see "The Proxmox SSH key" below).
# --ssh-host is optional and is NEVER derived from --url: when omitted the
# instance has no SSH host, so node shell, SFTP and file transfer stay
# disabled until you set one (the termproxy console works regardless).
# An explicit --ssh-host may include a port: --ssh-host pve:2222
ssh -p 2222 admin@proxpass instance add \
  --url https://pve:8006 \
  --token-id 'user@pam!token' \
  --token-secret 'uuid' \
  --console-transport ssh

# Override the SSH host/port explicitly (single --url only)
ssh -p 2222 admin@proxpass instance add \
  --name pve1 \
  --url https://pve1:8006 \
  --token-id 'user@pam!token' \
  --token-secret 'uuid' \
  --console-transport ssh \
  --ssh-host pve1.internal:2222

# Change an existing instance. Only the flags you pass are changed, and the
# instance keeps its id -- so its access rules survive, which re-adding it
# would not.
ssh -p 2222 admin@proxpass instance update --name pve1 --ssh-host pve1.internal:2222
ssh -p 2222 admin@proxpass instance update --name pve1 --token-id 'user@pam!new' --token-secret 'uuid'
ssh -p 2222 admin@proxpass instance update --name pve1 --rename pve-old

ssh -p 2222 admin@proxpass instance rm --name pve1

# Pin a node's SSH host key when it has no DNSSEC-validated SSHFP record.
# Adding an ssh-transport instance fails with the presented fingerprint when
# the host key cannot be verified; confirm it out of band, then pin it:
ssh -p 2222 admin@proxpass instance update --name pve1 \
  --ssh-fingerprint "SHA256:abc123...the/value/printed/by/the/failure"

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

## REST API

Every admin CLI command is a thin client over a typed REST API. `proxpass
serve` runs as root and owns the database and the key material; the CLI — and
any other client — reaches it over HTTP. This is why the CLI needs no database
access of its own: a client session holds a bearer token, nothing more.

The API is described by [`api/openapi.yaml`](api/openapi.yaml), and both the
server and the Go client are generated from it, so the spec cannot drift from
the implementation. Admin operations live under `/v1`; one resource per
operation rather than a generic exec endpoint.

### One listener, per-surface tokens

**Everything is served on a single listener** (`--listen`, `127.0.0.1:8080` by
default): the NSS user/group directory, the session API, the `/v1` admin API,
and the admin UI. There is no second socket. Each surface gates itself with its
own token, so the one socket can be exposed without the directory and the admin
API leaking into each other:

- The **NSS directory routes** (`/users`, `/user/...`, `/groups`, `/group/...`)
  are reachable **only** with `PROXPASS_NSS_TOKEN`. A request with no token, the
  wrong token, or the admin token is a 401. The container entrypoint generates
  this token at first start and hands it to `libnss_http` via the `Headers` map
  in `/etc/nss_http.json`, so `libnss_http` presents it on every lookup. If no
  NSS token is configured at all, the directory routes are **closed**, never
  opened.
- The **`/v1` admin API** is reachable **only** with an administrator credential:
  `PROXPASS_REST_API_TOKEN` (a static token for external clients / the UI), or a
  session credential minted by an admin SSH login (the token the CLI uses).

To reach the admin API and UI from outside the container, bind the listener
off loopback — set `PROXPASS_LISTEN=0.0.0.0:8080` and publish the port. Because
the two surfaces are independently token-gated, exposing the socket is safe: a
caller with the admin token cannot read the directory, and `libnss_http`'s NSS
token cannot reach `/v1`.

### Example

Expose the one listener and call the admin API directly, using a token in the
compose file:

```yaml
environment:
  PROXPASS_LISTEN: "0.0.0.0:8080"
  PROXPASS_REST_API_TOKEN: "s3cr3t-admin-token"
ports:
  - "8080:8080"
```

```bash
# List instances. Single-quote the token in case it contains shell
# metacharacters (a "!" triggers history expansion inside double quotes).
curl -H 'Authorization: Bearer s3cr3t-admin-token' \
  http://host:8080/v1/instances

# Add a client. Field names mirror the Go model: public_keys and group_ids
# are arrays; id is server-assigned and ignored on create.
curl -X POST -H 'Authorization: Bearer s3cr3t-admin-token' \
  -H 'Content-Type: application/json' \
  -d '{"id":0,"name":"alice","public_keys":["ssh-ed25519 AAAA... alice"],"group_ids":[]}' \
  http://host:8080/v1/clients
```

