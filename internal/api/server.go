package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/proxmox"
	"proxpass/internal/webui"
)

const (

	// LoginShell must be a REAL, executable shell.
	//
	// sshd runs ForceCommand through the account's login shell, so a
	// "no shell" value such as /usr/sbin/nologin or /bin/false breaks every
	// session. Confinement comes from ForceCommand, not from this field.
	LoginShell = "/bin/sh"

	// HomeDir is shared by all proxpass users. Sessions never touch the
	// filesystem; if the directory is absent sshd logs a harmless
	// "could not chdir to home directory" warning and continues.
	HomeDir = "/var/empty/proxpass"

	// shadowPasswd must NOT be one of the intuitive "locked account" markers
	// ("!", "!!", "*", or empty).
	//
	// The image runs sshd with UsePAM no, so sshd performs its own shadow
	// check and refuses a locked account outright — "User ... not allowed
	// because account is locked" — even for pure public-key authentication.
	// "x" means "the real secret lives in shadow", which is both true here
	// and accepted by sshd. Password auth is disabled in sshd_config, so
	// this never grants a password login.
	shadowPasswd = "x"

	// readHeaderTimeout bounds slow-loris clients on the loopback listener.
	readHeaderTimeout = 10 * time.Second

	// AdminUser is the reserved administrator login. It has no client row in
	// the database — it is authorized purely by the admin key list — but it
	// still has to resolve through NSS, otherwise sshd rejects the login as
	// an "invalid user" before it ever consults AuthorizedKeysCommand.
	AdminUser = "admin"

	// AliasUser is the name reported for the shared alias uid.
	//
	// A uid cannot say which alias a session logged in with -- every alias
	// resolves to the same one -- so the reverse lookup answers with this
	// placeholder rather than inventing a name. It is not itself a login:
	// any unused name works, and this one is served like any other alias.
	AliasUser = "proxpass-login"

	// SharedGroup is the primary group of every client login. It grants
	// READ access to the proxpass state directory, which is all a client
	// session needs: it resolves a guest, checks access and connects.
	//
	// This is a PRIMARY group rather than a supplementary one. Supplementary
	// membership would not work: glibc builds that list with initgroups(),
	// which enumerates the group database, and enumeration has to stay
	// disabled because sshd's late getgrent() crashes the sshd child from
	// inside the Go runtime embedded in libnss_http.so.2. A primary gid is
	// read straight from the passwd entry, so it needs no enumeration.
	SharedGroup    = "proxpass"
	SharedGroupGID = 19000

	// AdminGroup is the name of the admin login's primary group. Only it may
	// WRITE the database, because only the admin CLI modifies it. Keeping
	// clients out of this group means a client session cannot tamper with
	// another client's access rules.
	AdminGroup = "proxpass-admin"
)

// adminUser is the synthetic NSS entry for the reserved admin login.
func (l IDLayout) adminUser() User {
	return l.adminUserAs(AdminUser)
}

// aliasUser is the NSS entry for a login name that is not a configured
// account.
//
// Serving such a name is what makes it usable at all: sshd resolves the
// login through NSS and rejects an unknown one as "Invalid user" BEFORE it
// consults AuthorizedKeysCommand, so an unserved name could never reach the
// key check. The name itself means nothing -- the session identifies the
// caller from the key that authenticated (see session.ResolveIdentityByKey).
//
// It is therefore served with the LEAST privilege that still works: the
// shared client gid.
//
// That gid no longer grants anything on its own. It used to -- the database
// was group-writable, so an admin-gid alias would have let a client modify
// another client's access rules from the filesystem. The admin CLI then
// moved behind the API and the file became 0600 inside a 2700 directory, so
// group mode is zero and only `proxpass serve' opens it. The entrypoint
// records the same thing where it sets those modes.
//
// The least-privilege choice is kept regardless, because it costs nothing
// and the next thing to key off a gid should not find the wrong one here.
//
// The uid is AliasUID: shared by every alias, since NSS is asked only for a
// name and cannot tell one alias session from another, but distinct from the
// administrator's. An alias is reachable with any valid key, including a
// client's, so an alias session must not be indistinguishable from the
// admin's to anything that identifies a process by its owner.
func (l IDLayout) aliasUser(name string) User {
	return User{
		User:     name,
		Passwd:   shadowPasswd,
		Name:     "proxpass login",
		Dir:      HomeDir,
		Shell:    LoginShell,
		Uid:      l.AliasUID,
		Gid:      l.SharedGroupGID,
		AuthKeys: []string{},
	}
}

// adminUserAs is the reserved admin login's entry.
//
// Unlike an alias this does carry the admin gid, because the database is
// writable only by that group and the admin CLI has to write it. It is
// served ONLY for the reserved name; see handleUserByName.
func (l IDLayout) adminUserAs(name string) User {
	return User{
		User:     name,
		Passwd:   shadowPasswd,
		Name:     "proxpass administrator",
		Dir:      HomeDir,
		Shell:    LoginShell,
		Uid:      l.AdminUID,
		Gid:      l.AdminGroupGID,
		AuthKeys: []string{},
	}
}

// errIDOutOfRange marks a client whose derived uid cannot be represented
// inside a user-namespaced container.
var errIDOutOfRange = errors.New("id out of range")

// Server serves the nss_http user/group directory, the session API, and the
// typed /v1 admin REST API, all backed by the proxpass database.
type Server struct {
	repo   db.Repository
	logger *log.Logger
	ids    IDLayout

	// nssTokenHash, when non-empty, is the SHA-256 hash of the bearer token
	// the NSS routes require (PROXPASS_NSS_TOKEN). libnss_http presents it via
	// the Headers map in /etc/nss_http.json. Empty leaves the NSS routes open,
	// which is only safe on a loopback-only listener. Set with WithNSSToken.
	nssTokenHash string

	// restAPIToken is the static admin bearer token for the /v1 admin API,
	// passed through to the SessionHandler. Empty disables the static path.
	restAPIToken string

	// discoverer backs the admin RunDiscovery handler; nil disables it.
	discoverer proxmox.DiscovererFactory

	// protectedAdminKey is the configured PROXPASS_ADMIN_KEY, passed through to
	// the SessionHandler so RemoveAdminKey refuses to delete it. Empty protects
	// nothing. Set with WithProtectedAdminKey.
	protectedAdminKey string

	// settings is the effective serve configuration, passed through to the
	// SessionHandler for the read-only ListSettings view. Nil until set with
	// WithSettings.
	settings *SettingsSnapshot
}

// NewServer builds the directory server with the default id layout.
func NewServer(repo db.Repository, logger *log.Logger) *Server {
	return NewServerWithIDs(repo, logger, DefaultIDLayout())
}

// NewServerWithIDs builds the directory server with an explicit id layout.
func NewServerWithIDs(repo db.Repository, logger *log.Logger, ids IDLayout) *Server {
	return &Server{repo: repo, logger: logger, ids: ids}
}

// WithNSSToken requires the given bearer token on the NSS directory routes.
// An empty token leaves them open (loopback-only deployments). Chainable.
func (s *Server) WithNSSToken(token string) *Server {
	if token == "" {
		s.nssTokenHash = ""
		return s
	}
	s.nssTokenHash = HashToken(token)
	return s
}

// WithRESTAPIToken sets the static admin bearer token for the /v1 admin API.
// Chainable.
func (s *Server) WithRESTAPIToken(token string) *Server {
	s.restAPIToken = token
	return s
}

// WithDiscoverer wires the guest discoverer the admin RunDiscovery handler
// uses. Chainable.
func (s *Server) WithDiscoverer(factory proxmox.DiscovererFactory) *Server {
	s.discoverer = factory
	return s
}

// WithProtectedAdminKey passes the configured admin key through to the session
// handler so RemoveAdminKey refuses to delete it. Chainable.
func (s *Server) WithProtectedAdminKey(key string) *Server {
	s.protectedAdminKey = key
	return s
}

// WithSettings passes the effective serve configuration through to the session
// handler for the read-only ListSettings view. Chainable.
func (s *Server) WithSettings(snap *SettingsSnapshot) *Server {
	s.settings = snap
	return s
}

// IDs returns the layout the server serves.
func (s *Server) IDs() IDLayout { return s.ids }

// Handler returns the HTTP routes implementing the nss_http contract.
//
// Note on /users and /groups: the deployed /etc/nss_http.json sets
// AllowListingOfUsers and AllowListingOfGroups to false, so NSS never calls
// the enumeration endpoints. That is deliberate. With enumeration enabled,
// sshd's late getgrent() call — made after it has closed spare file
// descriptors — kills the sshd child from inside the Go runtime embedded in
// libnss_http.so.2 ("runtime: netpollBreak write failed with 9"). All real
// resolution therefore goes through the single-entry lookups. The list
// endpoints remain implemented because they are part of the contract.
//
// The session routes (/healthz and /session/...) are registered from the
// generated OpenAPI handler, so the spec in api/openapi.yaml stays the one
// description of them. The NSS routes above are hand-written for the reason
// given in that spec: their shape is fixed by an external consumer.
//
// Only the session routes are behind the bearer token. The NSS routes must
// stay open: nss_http sends no Authorization header, and sshd resolves the
// login through NSS before any session -- and therefore any token -- exists.
// The entrypoint also polls /users to decide when the directory is ready, so
// requiring a token there would deadlock container startup.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	nss := s.nssAuth

	// The NSS directory routes are hand-written -- their JSON is the nss_http
	// wire format, not a resource proxpass designed -- so they are registered
	// directly on the chi router the generated handler also mounts onto. The
	// trailing "/*" matches the subtree ServeMux's trailing-slash patterns did;
	// each handler reads the full r.URL.Path, so no chi URL param is involved.
	r.HandleFunc("/user/name/*", nss(s.handleUserByName))
	r.HandleFunc("/user/uid/*", nss(s.handleUserByUID))
	r.HandleFunc("/users", nss(s.handleUsers))
	r.HandleFunc("/group/name/*", nss(s.handleGroupByName))
	r.HandleFunc("/group/gid/*", nss(s.handleGroupByGID))
	r.HandleFunc("/groups", nss(s.handleGroups))

	// The SSH-key operations are the one remaining /admin/rpc endpoint: they
	// read a root-owned key file on an admin session's behalf and have no /v1
	// resource (see adminrpc.go). They authorize themselves against an admin
	// identity. Loopback only -- the session asks the local `serve' process --
	// so this is registered on the loopback Handler, not on AdminHandler.
	r.HandleFunc("/admin/rpc", s.ServeAdminRPC)

	// The admin web UI and /openapi.json are served from this listener too.
	s.mountWebUI(r)

	// The session API and the typed /v1 admin REST API are both served by the
	// generated strict handler (one SessionHandler implements both), mounted
	// onto the same chi router via the generated HandlerFromMux. Admin
	// operations authorize themselves against an admin identity -- a session
	// credential whose stored identity is the administrator's, or the static
	// PROXPASS_REST_API_TOKEN. The old /admin/rpc tagged-union endpoint is gone;
	// its operations are now the typed /v1 resources.
	return HandlerWithOptions(
		NewStrictHandler(s.sessionHandler(), nil),
		ChiServerOptions{
			BaseRouter:  r,
			Middlewares: []MiddlewareFunc{bearerTokenMiddleware},
		},
	)
}

// mountWebUI registers the static admin SPA and the /openapi.json spec route on
// a chi router, before the generated API routes are attached.
//
// The SPA is mounted as a catch-all (NotFound), not as a greedy "/*" route:
// chi dispatches an incoming request to the most specific matching pattern, so
// every generated API route (/v1/..., /session/..., /healthz) and the NSS and
// /admin/rpc routes still win. Only paths that match nothing else -- "/", the
// SPA's assets, an unknown sub-path -- fall through to the UI. That keeps the
// API authoritative while letting the UI own the rest of the origin.
//
// The whole thing is same-origin with the API it drives, so no CORS is needed;
// the UI authenticates with a bearer token it holds in memory (see the
// frontend), never a cookie, so there is nothing for a CSRF to ride.
func (s *Server) mountWebUI(r chi.Router) {
	// The embedded spec is public shape, not secrets, and the UI (or any
	// client) may fetch it to render or to generate a typed client. It is a
	// plain GET with no auth, like /healthz.
	r.Get("/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		spec, err := GetSpecJSON()
		if err != nil {
			http.Error(w, "spec unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(spec)
	})

	// NotFound catches everything the API did not claim and hands it to the
	// SPA's file server, which serves index.html for "/" and the built assets
	// for their paths (404 for a genuinely missing file).
	ui := webui.Handler()
	r.NotFound(ui.ServeHTTP)
}

// AdminHandler returns a handler that serves ONLY the session + /v1 admin API,
// WITHOUT the NSS directory routes. It is used for a second, routable listener
// (PROXPASS_REST_API_LISTEN) so the admin REST API can be exposed off-loopback
// without also exposing the user/group directory. Every /v1 operation still
// requires an admin credential.
func (s *Server) AdminHandler() http.Handler {
	r := chi.NewRouter()

	// The admin UI is served here too: this is the listener a remote admin
	// reaches, so it is exactly where the UI needs to be available. It serves
	// no NSS routes, so the UI does not expose the directory.
	s.mountWebUI(r)

	return HandlerWithOptions(
		NewStrictHandler(s.sessionHandler(), nil),
		ChiServerOptions{
			BaseRouter:  r,
			Middlewares: []MiddlewareFunc{bearerTokenMiddleware},
		},
	)
}

// sessionHandler builds the generated-API handler with the server's optional
// admin wiring (static REST token, discoverer, protected admin key).
func (s *Server) sessionHandler() *SessionHandler {
	return NewSessionHandler(s.repo, s.logger).
		WithRESTAPIToken(s.restAPIToken).
		WithDiscoverer(s.discoverer).
		WithProtectedAdminKey(s.protectedAdminKey).
		WithSettings(s.settings)
}

// nssAuth wraps an NSS handler with the optional NSS bearer-token check. When
// no NSS token is configured the handler is returned unchanged, so a
// loopback-only deployment keeps the open directory it had.
//
// The token is verified in constant time. A missing or wrong token is a 401;
// libnss_http turns that into "user not found", so a misconfigured token
// fails closed rather than leaking the directory.
func (s *Server) nssAuth(next http.HandlerFunc) http.HandlerFunc {
	if s.nssTokenHash == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := BearerToken(withBearerToken(r).Context())
		if !ok || subtle.ConstantTimeCompare(
			[]byte(HashToken(token)), []byte(s.nssTokenHash)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// bearerTokenMiddleware puts the Authorization header on the request context
// for the session handlers.
//
// It does not reject anything. Whether a token is good is decided by
// redeeming it, which consumes it, so that has to happen once in the handler
// that needs the answer -- see GetSessionIdentity. /healthz is specified as
// unauthenticated and simply ignores the context value.
func bearerTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, withBearerToken(r))
	})
}

// ListenAndServe runs the full directory + session + admin server (NSS routes
// included) until ctx is canceled. This is the loopback listener.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	return serveHTTP(ctx, addr, s.Handler(), "directory server")
}

// ListenAndServeAdmin runs a second listener serving ONLY the session + /v1
// admin API (no NSS routes), for exposing the admin REST API off-loopback.
// Runs until ctx is canceled.
func (s *Server) ListenAndServeAdmin(ctx context.Context, addr string) error {
	return serveHTTP(ctx, addr, s.AdminHandler(), "admin REST server")
}

// serveHTTP runs one http.Server until ctx is canceled, then drains it.
func serveHTTP(ctx context.Context, addr string, handler http.Handler, name string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	//nolint:gosec // G118: the shutdown deadline must outlive ctx, which has
	// just been canceled; deriving from it would abort the drain immediately.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// UserFor converts a proxpass client into its NSS user entry.
//
// A client whose derived uid would exceed maxID is not representable: see
// UIDBase. Callers should skip such a client rather than publish an entry
// sshd cannot use; handleUsers and handleUserByName do.
func (l IDLayout) UserFor(c *models.Client) User {
	uid := l.UIDFor(c.ID)
	return User{
		User:     c.Name,
		Passwd:   shadowPasswd,
		Name:     "proxpass client " + c.Name,
		Dir:      HomeDir,
		Shell:    LoginShell,
		Uid:      uid,
		Gid:      l.SharedGroupGID,
		AuthKeys: []string{},
	}
}

// GroupFor converts a proxpass group into its NSS group entry. members are the
// names of the clients belonging to the group.
func (l IDLayout) GroupFor(g *models.Group, members []string) Group {
	if members == nil {
		members = []string{}
	}
	return Group{
		Name:         g.Name,
		Passwd:       shadowPasswd,
		Gid:          l.GIDFor(g.ID),
		GroupMembers: members,
	}
}

func (s *Server) handleUserByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/user/name/")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	// Case-insensitive, like every other test against the reserved name:
	// isReservedLoginName, IsLoginNameReserved and ValidateClientName all
	// use EqualFold. This one did not, so "ADMIN" was reserved everywhere
	// except where its directory entry was chosen -- it reached the picker
	// as a reserved name while being served the shared ALIAS uid.
	//
	// Nothing is granted by the entry either way. The admin gid has been
	// powerless since the admin CLI moved behind the API: the state
	// directory is 2700 and the database 0600, so group mode is zero and
	// every session, privileged or not, reaches the database through
	// `proxpass serve'. Authority comes from the KEY -- IsAdmin is set in
	// authorizedkeys.go and travels in the minted token -- so `ssh
	// ADMIN@host' with a client's key was and remains a client session.
	//
	// What changes is the uid, in the direction IDLayout.AliasUID asks for:
	// aliases deliberately SHARE a uid and so must not be mistaken for the
	// administrator by anything keying off process ownership. Serving the
	// reserved name from the alias pool was exactly that mistake.
	if models.NamesEqual(name, AdminUser) {
		s.writeJSON(w, s.ids.adminUserAs(name))
		return
	}
	client, err := s.repo.GetClientByName(r.Context(), name)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Not a client: serve it as an administrator alias so sshd gets far
		// enough to ask for a key. See adminUserAs.
		s.writeAdminAlias(w, r, name)
	case err != nil:
		// A real backend fault must NOT be reported as 404: nss_http reads
		// 404 as "no such user", so sshd would reject the login pre-auth as
		// an invalid user and a storage problem would look like a deleted
		// account.
		s.fail(w, fmt.Sprintf("user %q lookup", name), err)
	case client == nil:
		s.writeAdminAlias(w, r, name)
	default:
		user := s.ids.UserFor(client)
		if !s.ids.InRange(user.Uid) {
			// Not representable inside a user namespace; sshd would accept
			// the key and then fail with "setresuid ...: Invalid argument".
			// Refusing here at least fails cleanly and visibly.
			s.fail(w, fmt.Sprintf("user %q uid %d exceeds the maximum of %d",
				name, user.Uid, s.ids.MaxID), errIDOutOfRange)
			return
		}
		s.writeJSON(w, user)
	}
}

// writeAdminAlias serves name as an administrator alias, or 404s when the
// name could not be a login name at all.
//
// Refusing a syntactically invalid name matters: the name is echoed into a
// passwd entry, so it must not be able to carry a colon, a newline or a
// shell metacharacter.
func (s *Server) writeAdminAlias(w http.ResponseWriter, r *http.Request, name string) {
	if !ValidLoginName(name) {
		http.NotFound(w, r)
		return
	}
	s.writeJSON(w, s.ids.aliasUser(name))
}

func (s *Server) handleUserByUID(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/user/uid/")
	uid, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// The alias uid resolves to the reserved alias name rather than to any
	// particular alias: a uid cannot say which name a session logged in
	// with, since every alias shares it. Answering keeps `ls -l` and the
	// like from showing a bare number for a session's own files.
	if uid == uint64(s.ids.AliasUID) {
		s.writeJSON(w, s.ids.aliasUser(AliasUser))
		return
	}
	if uid == uint64(s.ids.AdminUID) {
		s.writeJSON(w, s.ids.adminUser())
		return
	}
	// Below the fixed uids there is nothing proxpass serves; the lowest
	// client uid is UIDBase.
	if uid < uint64(s.ids.UIDBase) {
		http.NotFound(w, r)
		return
	}
	clients, err := s.repo.ListClients(r.Context())
	if err != nil {
		s.fail(w, "list clients", err)
		return
	}
	for _, c := range clients {
		if u := s.ids.UserFor(c); uint64(u.Uid) == uid {
			s.writeJSON(w, u)
			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	clients, err := s.repo.ListClients(r.Context())
	if err != nil {
		s.fail(w, "list clients", err)
		return
	}
	users := make([]User, 0, len(clients)+1)
	users = append(users, s.ids.adminUser())
	for _, c := range clients {
		u := s.ids.UserFor(c)
		if !s.ids.InRange(u.Uid) {
			s.logger.Printf("directory: skipping user %q: uid %d exceeds %d",
				c.Name, u.Uid, s.ids.MaxID)
			continue
		}
		users = append(users, u)
	}
	s.writeJSON(w, users)
}

func (s *Server) handleGroupByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/group/name/")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	groups, err := s.allGroups(r.Context())
	if err != nil {
		s.fail(w, "list groups", err)
		return
	}
	// Case-insensitive, matching the user lookup above and the CLI. A group
	// entry carries a gid but confers nothing: group membership is not an
	// authorization input anywhere -- access rules are resolved by the API
	// from the caller's identity, never from a gid -- and the shared and
	// admin groups are not enumerable at all (see SharedGroup).
	for i := range groups {
		if models.NamesEqual(groups[i].Name, name) {
			s.writeJSON(w, groups[i])
			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) handleGroupByGID(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/group/gid/")
	gid, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	groups, err := s.allGroups(r.Context())
	if err != nil {
		s.fail(w, "list groups", err)
		return
	}
	for i := range groups {
		if uint64(groups[i].Gid) == gid {
			s.writeJSON(w, groups[i])
			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.allGroups(r.Context())
	if err != nil {
		s.fail(w, "list groups", err)
		return
	}
	s.writeJSON(w, groups)
}

// allGroups returns the per-user primary groups followed by the proxpass
// groups, which is the full set of groups NSS should see.
func (s *Server) allGroups(ctx context.Context) ([]Group, error) {
	clients, err := s.repo.ListClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
	}
	groups, err := s.repo.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing groups: %w", err)
	}

	byID := make(map[int64]string, len(clients))
	// The shared group is every client's primary group, so it also lists
	// them as members. That is cosmetic — "getent group proxpass" shows who
	// can read the state directory — since access comes from the primary gid
	// in each passwd entry. The admin is deliberately NOT a member: it has
	// its own group, which is the only one with write access.
	shared := Group{
		Name:         SharedGroup,
		Passwd:       shadowPasswd,
		Gid:          s.ids.SharedGroupGID,
		GroupMembers: make([]string, 0, len(clients)),
	}
	// The admin group has exactly one member and grants write access.
	adminGrp := Group{
		Name:         AdminGroup,
		Passwd:       shadowPasswd,
		Gid:          s.ids.AdminGroupGID,
		GroupMembers: []string{AdminUser},
	}

	out := make([]Group, 0, len(groups)+3)
	out = append(out, adminGrp)
	for _, c := range clients {
		byID[c.ID] = c.Name
		shared.GroupMembers = append(shared.GroupMembers, c.Name)
	}
	out = append(out, shared)
	for _, g := range groups {
		members := make([]string, 0, len(g.ClientIDs))
		for _, id := range g.ClientIDs {
			if name, ok := byID[id]; ok {
				members = append(members, name)
			}
		}
		out = append(out, s.ids.GroupFor(g, members))
	}
	return out, nil
}

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.logger.Printf("directory: encoding response: %v", err)
	}
}

// fail reports a genuine backend error. It must not be a 404: nss_http treats
// 404 as "no such user", which would turn a database outage into a silent
// authentication failure.
func (s *Server) fail(w http.ResponseWriter, what string, err error) {
	s.logger.Printf("directory: %s: %v", what, err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}
