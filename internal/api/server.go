package api

import (
	"context"
	"encoding/json"
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
	// UIDBase is added to a client's database id to derive its Unix uid, and
	// GIDBase likewise for groups. Debian allocates uids below 1000 to system
	// accounts and the local adduser range starts at 1000, so starting well
	// above that keeps proxpass users from ever colliding with an account in
	// /etc/passwd. nsswitch consults "files" before "http", so a collision
	// would silently shadow the proxpass user.
	UIDBase = 100000
	GIDBase = 200000

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

	// AdminUID is the fixed uid/gid of the reserved admin account. It sits
	// just below UIDBase so it can never collide with a client, whose uid is
	// always UIDBase plus a positive row id.
	AdminUID = UIDBase - 1

	// SharedGroup owns the proxpass state directory. "proxpass session" runs
	// as the logged-in user rather than as root, so every login needs group
	// access to the database.
	//
	// This is each user's PRIMARY group rather than a supplementary one.
	// Supplementary membership would not work: glibc builds that list with
	// initgroups(), which enumerates the group database, and enumeration has
	// to stay disabled because sshd's late getgrent() crashes the sshd child
	// from inside the Go runtime embedded in libnss_http.so.2. A primary gid
	// is read straight from the passwd entry, so it needs no enumeration.
	//
	// Sharing one primary group across logins is acceptable here because a
	// session is confined by sshd's ForceCommand and never gets a shell.
	SharedGroup    = "proxpass"
	SharedGroupGID = 64000
)

// adminUser is the synthetic NSS entry for the reserved admin login.
func adminUser() User {
	return User{
		User:     AdminUser,
		Passwd:   shadowPasswd,
		Name:     "proxpass administrator",
		Dir:      HomeDir,
		Shell:    LoginShell,
		Uid:      AdminUID,
		Gid:      SharedGroupGID,
		AuthKeys: []string{},
	}
}

// Server serves the nss_http user/group directory backed by the proxpass
// database.
type Server struct {
	repo   db.Repository
	logger *log.Logger
}

// NewServer builds the directory server.
func NewServer(repo db.Repository, logger *log.Logger) *Server {
	return &Server{repo: repo, logger: logger}
}

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
func UserFor(c *models.Client) User {
	//nolint:gosec // client ids are small positive sqlite rowids
	uid := uint(c.ID) + UIDBase
	return User{
		User:     c.Name,
		Passwd:   shadowPasswd,
		Name:     "proxpass client " + c.Name,
		Dir:      HomeDir,
		Shell:    LoginShell,
		Uid:      uid,
		Gid:      SharedGroupGID,
		AuthKeys: c.PublicKeys,
	}
}

// GroupFor converts a proxpass group into its NSS group entry. members are the
// names of the clients belonging to the group.
func GroupFor(g *models.Group, members []string) Group {
	if members == nil {
		members = []string{}
	}
	//nolint:gosec // group ids are small positive sqlite rowids
	return Group{
		Name:         g.Name,
		Passwd:       shadowPasswd,
		Gid:          uint(g.ID) + GIDBase,
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
		s.writeJSON(w, adminUser())
		return
	}
	client, err := s.repo.GetClientByName(r.Context(), name)
	if err != nil || client == nil {
		// GetClientByName reports a missing row as an error, so an error here
		// is treated as "no such user" rather than a server fault. Logging it
		// keeps a real database problem visible.
		if err != nil {
			s.logger.Printf("directory: user %q lookup: %v", name, err)
		}
		http.NotFound(w, r)
		return
	}
	s.writeJSON(w, UserFor(client))
}

func (s *Server) handleUserByUID(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/user/uid/")
	uid, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || uid < AdminUID {
		http.NotFound(w, r)
		return
	}
	if uid == AdminUID {
		s.writeJSON(w, adminUser())
		return
	}
	clients, err := s.repo.ListClients(r.Context())
	if err != nil {
		s.fail(w, "list clients", err)
		return
	}
	for _, c := range clients {
		if u := UserFor(c); uint64(u.Uid) == uid {
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
	users = append(users, adminUser())
	for _, c := range clients {
		users = append(users, UserFor(c))
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
	// The shared group is every login's primary group, so it also lists them
	// as members. That is only cosmetic — "getent group proxpass" shows who
	// can reach the state directory — since access comes from the primary
	// gid in each passwd entry.
	shared := Group{
		Name:         SharedGroup,
		Passwd:       shadowPasswd,
		Gid:          SharedGroupGID,
		GroupMembers: make([]string, 0, len(clients)+1),
	}
	shared.GroupMembers = append(shared.GroupMembers, AdminUser)

	out := make([]Group, 0, len(groups)+2)
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
		out = append(out, GroupFor(g, members))
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
