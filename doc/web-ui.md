# Admin web UI

## Admin Web UI

proxpass ships a browser admin UI for the REST API. It is a static
single-page app — TailwindCSS and Alpine.js — compiled into the binary, so the
same proxpass process that serves `/v1` serves the UI with no separate web
server, no Node.js runtime, and no external files.

### Exposing it

The container's one HTTP listener is **loopback-only by default**
(`PROXPASS_LISTEN` is `127.0.0.1:8080`), so nothing is reachable from outside
the container until you ask for it. To reach the UI from your browser, bind the
listener off loopback and publish its port:

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

`PROXPASS_LISTEN=0.0.0.0:8080` binds the listener to all interfaces, and
`PROXPASS_REST_API_TOKEN` is the token you will log in with. Exposing this one
socket is safe because each surface is independently token-gated: the NSS
directory requires `PROXPASS_NSS_TOKEN` (the container generates it), and the
admin API and UI require the admin token above. Pick a long random admin token
and serve the listener over TLS if it is reachable beyond localhost.

The same works in a compose file:

```yaml
services:
  proxpass:
    image: ghcr.io/eun/proxpass:latest
    ports:
      - "2222:22"
      - "8080:8080"
    volumes:
      - proxpass-data:/var/lib/proxpass
    environment:
      PROXPASS_ADMIN_KEY: "ssh-ed25519 AAAA… you"
      PROXPASS_LISTEN: "0.0.0.0:8080"
      PROXPASS_REST_API_TOKEN: "a-long-random-secret"
```

### Logging in

1. Open **`http://localhost:8080/`** (or wherever you published the listener).
2. You are asked for an **admin API token**. Paste the value of
   `PROXPASS_REST_API_TOKEN` — that token *is* the login. (An admin session
   token minted over SSH also works, but the static token is the simple path.)
3. Click **Sign in**. The token is checked against the API and, if valid, the
   dashboard loads.

The UI keeps the token only in the browser tab's memory — never a cookie — so
it is not exposed to CSRF, is forgotten when the tab closes, and signing out
clears it immediately. Because the token grants full admin access, pick a long
random value (`openssl rand -hex 32`), serve the listener over TLS if it is
reachable beyond localhost, and rotate it by restarting with a new value.

The UI covers every admin resource: instances, guests, clients, groups, guest
and node access rules, the default policy, admin keys, settings, and running
discovery — the same operations as the [Admin CLI](admin-cli.md#admin-cli). The OpenAPI
spec the UI is built against is also served, at `/openapi.json`, for generating
clients or exploring the API.

### Building the UI

The UI is built into the binary at compile time and the built assets are
committed, so a plain `go build` or the container image already includes it —
there is nothing extra to run for a normal build or deployment.

To rebuild it after changing `frontend/`, run:

```bash
mise run frontend   # or `mise run build`, which depends on it
```

This uses the mise-pinned Tailwind **standalone** CLI (a single binary; no
`npm install`, no `node_modules`) to compile `frontend/` into
`internal/webui/dist/`. Alpine.js and Chart.js are vendored under
`frontend/assets/js/` rather than loaded from a CDN, so the UI works with no
outbound network. The pinned toolchain is in `mise.toml`, so local builds, CI,
and the release all compile the UI the same way.

