package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"proxpass/internal/db"
	"proxpass/internal/models"
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

// adminUserAs is the admin entry under an arbitrary login name.
//
// Any name that is not a client resolves to the administrator, which restores
// the behavior proxpass had when it ran its own SSH server: the connection
// was authenticated by the key alone and the login name was cosmetic, so
// "ssh tobias@proxpass" worked with an admin key.
//
// sshd cannot work that way, because it resolves the login name through NSS
// and rejects an unknown one as "Invalid user" BEFORE it ever consults
// AuthorizedKeysCommand. Serving the name is therefore what makes it usable
// at all. It grants nothing on its own: every alias shares the admin uid and
// gid, and only an admin key authorizes it -- see WriteAuthorizedKeys, which
// offers admin keys and never a client's for such a name.
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

// Server serves the nss_http user/group directory backed by the proxpass
// database.
type Server struct {
	repo   db.Repository
	logger *log.Logger
	ids    IDLayout
}

// NewServer builds the directory server with the default id layout.
func NewServer(repo db.Repository, logger *log.Logger) *Server {
	return NewServerWithIDs(repo, logger, DefaultIDLayout())
}

// NewServerWithIDs builds the directory server with an explicit id layout.
func NewServerWithIDs(repo db.Repository, logger *log.Logger, ids IDLayout) *Server {
	return &Server{repo: repo, logger: logger, ids: ids}
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
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/user/name/", s.handleUserByName)
	mux.HandleFunc("/user/uid/", s.handleUserByUID)
	mux.HandleFunc("/users", s.handleUsers)
	mux.HandleFunc("/group/name/", s.handleGroupByName)
	mux.HandleFunc("/group/gid/", s.handleGroupByGID)
	mux.HandleFunc("/groups", s.handleGroups)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// ListenAndServe runs the directory server until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
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
		return fmt.Errorf("directory server: %w", err)
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
	if name == AdminUser {
		s.writeJSON(w, s.ids.adminUser())
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
	s.writeJSON(w, s.ids.adminUserAs(name))
}

func (s *Server) handleUserByUID(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/user/uid/")
	uid, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || uid < uint64(s.ids.AdminUID) {
		http.NotFound(w, r)
		return
	}
	if uid == uint64(s.ids.AdminUID) {
		s.writeJSON(w, s.ids.adminUser())
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
	for i := range groups {
		if groups[i].Name == name {
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
