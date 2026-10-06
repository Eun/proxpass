package api_test

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"proxpass/internal/api"
	"proxpass/internal/cli"
	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/session"
)

func newTestServer(t *testing.T) (http.Handler, db.Repository) {
	t.Helper()
	repo, err := db.NewSQLiteRepository(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	logger := log.New(io.Discard, "", 0)
	return api.NewServer(repo, logger).Handler(), repo
}

func seedClient(t *testing.T, repo db.Repository, name string, keys ...string) *models.Client {
	t.Helper()
	c := &models.Client{Name: name, PublicKeys: keys}
	if err := repo.AddClient(t.Context(), c); err != nil {
		t.Fatalf("add client %q: %v", name, err)
	}
	stored, err := repo.GetClientByName(t.Context(), name)
	if err != nil {
		t.Fatalf("get client %q: %v", name, err)
	}
	return stored
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(
		t.Context(), http.MethodGet, path, http.NoBody))
	return rec
}

const userAliceName = "alice"

func TestUserByName(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, userAliceName, "ssh-ed25519 AAAAkey alice")

	rec := get(t, h, "/user/name/alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var user api.User
	if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if user.User != "alice" {
		t.Errorf("User = %q, want alice", user.User)
	}
	// sshd runs with UsePAM no and does its own shadow check, so the
	// "locked account" markers make it refuse the login outright even for
	// public-key auth. Verified against a live sshd.
	for _, locked := range []string{"!", "!!", "*", ""} {
		if user.Passwd == locked {
			t.Errorf("Passwd = %q, which sshd treats as a locked account", user.Passwd)
		}
	}
	// Likewise the shell must be real: sshd runs ForceCommand through it.
	for _, noShell := range []string{"/bin/false", "/usr/sbin/nologin", ""} {
		if user.Shell == noShell {
			t.Errorf("Shell = %q, which breaks ForceCommand", user.Shell)
		}
	}
	if user.Uid < api.DefaultUIDBase {
		t.Errorf("Uid = %d, want >= %d to avoid colliding with system users",
			user.Uid, api.DefaultUIDBase)
	}
	if user.Shell == "" || user.Dir == "" {
		t.Errorf("Shell/Dir must be set, got %q/%q", user.Shell, user.Dir)
	}
}

// The capitalized JSON keys are the nss_http wire format. Lowercasing them
// would make every NSS lookup silently return an empty entry.
func TestUserJSONKeysAreCapitalized(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, userAliceName, "ssh-ed25519 AAAAkey alice")

	rec := get(t, h, "/user/name/alice")
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"User", "Passwd", "Name", "Dir", "Shell", "Uid", "Gid", "AuthKeys"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("response is missing required key %q; got %v", key, keysOf(raw))
		}
	}
}

// A name that is not a client resolves to the administrator, sharing the
// admin uid and gid. Without this sshd rejects the login as "Invalid user"
// before it ever asks for a key, so an admin could only ever log in as
// "admin" — proxpass used to accept any name when it ran its own SSH server.
func TestUnknownUserIsServedAsAnUnprivilegedAlias(t *testing.T) {
	h, _ := newTestServer(t)
	ids := api.DefaultIDLayout()

	// Names that are not valid for useradd but are perfectly serviceable
	// over NSS must work: proxpass is not reading /etc/passwd.
	for _, name := range []string{"Tobias", "1st-box", "tobias.b", "tobías"} {
		if !api.ValidLoginName(name) {
			t.Errorf("ValidLoginName(%q) = false, want it served", name)
		}
	}

	rec := get(t, h, "/user/name/tobias")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got api.User
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.User != "tobias" {
		t.Errorf("User = %q, want %q", got.User, "tobias")
	}
	// An alias must carry the SHARED gid, not the admin one.
	//
	// The alias is reachable with any valid key, a client's included, since
	// the name is not a credential. The admin gid can WRITE the database,
	// so granting it here would let a client edit another client's access
	// rules through the filesystem even though proxpass had correctly
	// resolved it as a non-admin.
	if got.Gid == ids.AdminGroupGID {
		t.Errorf("alias was served the admin gid %d; it can write the database",
			got.Gid)
	}
	if got.Gid != ids.SharedGroupGID {
		t.Errorf("gid = %d, want the shared client gid %d",
			got.Gid, ids.SharedGroupGID)
	}
	// An alias must NOT share the administrator's uid. An alias is reachable
	// with any valid key, including a client's, so a shared uid would make
	// an alias session indistinguishable from the admin's to anything that
	// identifies a process by its owner.
	if got.Uid != ids.AliasUID {
		t.Errorf("uid = %d, want the alias uid %d", got.Uid, ids.AliasUID)
	}
	if got.Uid == ids.AdminUID {
		t.Errorf("alias uid %d is the administrator's uid", got.Uid)
	}
}

// The reserved admin login still gets the admin gid: the admin CLI has to be
// able to write the database.
func TestAdminLoginKeepsTheWritableGid(t *testing.T) {
	h, _ := newTestServer(t)
	ids := api.DefaultIDLayout()

	rec := get(t, h, "/user/name/"+api.AdminUser)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got api.User
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Gid != ids.AdminGroupGID {
		t.Errorf("gid = %d, want the admin gid %d", got.Gid, ids.AdminGroupGID)
	}
}

// A name that cannot be a Unix login name must still 404: it is echoed into a
// passwd entry, so it must not be able to carry a colon or a newline.
func TestUnservableLoginNameIs404(t *testing.T) {
	h, _ := newTestServer(t)
	for _, name := range []string{
		"root:x:0:0", // forges a passwd entry
		"has space",  // rejected by the HTTP request line
		"alice\nbob", // forges a passwd record
		"alice%2f",   // an escape the server would decode differently
		"alice?x=1",  // resolved as "alice": a DIFFERENT user
		"alice#frag", // same
		"al/ice",     // adds a path segment
		"-alice",     // parsed as a flag by AuthorizedKeysCommand
		strings.Repeat("a", api.MaxLoginNameLen+1),
	} {
		// Escaped as a client would have to send it; the server sees the
		// decoded name in r.URL.Path either way.
		path := "/user/name/" + url.PathEscape(name)
		if rec := get(t, h, path); rec.Code != http.StatusNotFound {
			t.Errorf("name %q: status = %d, want 404", name, rec.Code)
		}
	}

	// "." and ".." never reach the handler at all: net/http cleans the path
	// and answers with a redirect, so the lookup lands somewhere else
	// entirely. They must still be refused as login names.
	for _, name := range []string{".", ".."} {
		if api.ValidLoginName(name) {
			t.Errorf("ValidLoginName(%q) = true, want it refused", name)
		}
	}
}

func TestUserByUID(t *testing.T) {
	h, repo := newTestServer(t)
	client := seedClient(t, repo, userAliceName, "ssh-ed25519 AAAAkey alice")
	want := api.DefaultIDLayout().UserFor(client)

	rec := get(t, h, "/user/uid/"+itoa(want.Uid))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var user api.User
	_ = json.Unmarshal(rec.Body.Bytes(), &user)
	if user.User != "alice" {
		t.Errorf("User = %q, want alice", user.User)
	}
}

// A uid below the proxpass range belongs to a system account and must not
// resolve through this API.
func TestSystemUIDIsNotServed(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, userAliceName)

	if rec := get(t, h, "/user/uid/0"); rec.Code != http.StatusNotFound {
		t.Errorf("uid 0: status = %d, want 404", rec.Code)
	}
}

func TestUsersList(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, userAliceName)
	seedClient(t, repo, "bob")

	rec := get(t, h, "/users")
	var users []api.User
	if err := json.Unmarshal(rec.Body.Bytes(), &users); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// alice, bob, plus the reserved admin account.
	if len(users) != 3 {
		t.Fatalf("got %d users, want 3 (alice, bob, admin)", len(users))
	}
	// uids must be distinct, or logins collide.
	seen := map[uint]string{}
	for _, u := range users {
		if prev, dup := seen[u.Uid]; dup {
			t.Errorf("uid %d is shared by %q and %q", u.Uid, prev, u.User)
		}
		seen[u.Uid] = u.User
	}
}

// sshd rejects a login as an "invalid user" before it ever runs
// AuthorizedKeysCommand, so the reserved admin account must resolve through
// NSS even though it has no row in the database.
func TestAdminResolves(t *testing.T) {
	h, _ := newTestServer(t)

	rec := get(t, h, "/user/name/"+api.AdminUser)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin lookup status = %d, want 200", rec.Code)
	}
	var user api.User
	_ = json.Unmarshal(rec.Body.Bytes(), &user)
	if user.User != api.AdminUser {
		t.Errorf("User = %q, want %q", user.User, api.AdminUser)
	}

	// And by uid, plus a matching primary group.
	if rec := get(t, h, "/user/uid/"+itoa(user.Uid)); rec.Code != http.StatusOK {
		t.Errorf("admin uid lookup status = %d, want 200", rec.Code)
	}
	if rec := get(t, h, "/group/gid/"+itoa(user.Gid)); rec.Code != http.StatusOK {
		t.Errorf("admin primary group lookup status = %d, want 200", rec.Code)
	}
}

// The admin uid must never collide with a client's.
func TestAdminUIDDoesNotCollideWithClients(t *testing.T) {
	h, repo := newTestServer(t)
	client := seedClient(t, repo, userAliceName)

	if api.DefaultIDLayout().UserFor(client).Uid == uint(api.DefaultUIDBase-1) {
		t.Errorf("client uid %d collides with the admin uid", uint(api.DefaultUIDBase-1))
	}
	if rec := get(t, h, "/user/uid/"+itoa(uint(api.DefaultUIDBase-1))); rec.Code != http.StatusOK {
		t.Errorf("admin uid must resolve, got %d", rec.Code)
	}
}

// Every user's primary gid must resolve to a real group, otherwise sshd
// cannot complete the login. All logins share one primary group, because
// supplementary groups would require NSS enumeration (which is disabled).
func TestEveryUserHasAPrimaryGroup(t *testing.T) {
	h, repo := newTestServer(t)
	client := seedClient(t, repo, userAliceName)
	user := api.DefaultIDLayout().UserFor(client)

	if user.Gid != uint(api.DefaultSharedGroupGID) {
		t.Errorf("primary gid = %d, want the shared gid %d", user.Gid, uint(api.DefaultSharedGroupGID))
	}

	rec := get(t, h, "/group/gid/"+itoa(user.Gid))
	if rec.Code != http.StatusOK {
		t.Fatalf("primary gid must resolve, got %d", rec.Code)
	}
	var group api.Group
	_ = json.Unmarshal(rec.Body.Bytes(), &group)
	if group.Name != api.SharedGroup {
		t.Errorf("group name = %q, want %q", group.Name, api.SharedGroup)
	}
}

func TestGroupMembership(t *testing.T) {
	h, repo := newTestServer(t)
	alice := seedClient(t, repo, userAliceName)
	bob := seedClient(t, repo, "bob")

	g := &models.Group{Name: "devs", ClientIDs: []int64{alice.ID, bob.ID}}
	if err := repo.AddGroup(t.Context(), g); err != nil {
		t.Fatalf("add group: %v", err)
	}

	rec := get(t, h, "/group/name/devs")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var group api.Group
	_ = json.Unmarshal(rec.Body.Bytes(), &group)

	if len(group.GroupMembers) != 2 {
		t.Fatalf("members = %v, want alice and bob", group.GroupMembers)
	}
	if group.Gid < api.DefaultGIDBase {
		t.Errorf("Gid = %d, want >= %d", group.Gid, api.DefaultGIDBase)
	}
}

// GroupMembers must serialize as [] rather than null: nss_http expects a
// list, and a null would be indistinguishable from a decode failure.
func TestEmptyGroupMembersSerializeAsArray(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, userAliceName)

	rec := get(t, h, "/group/name/"+api.SharedGroup)
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	members, ok := raw["GroupMembers"]
	if !ok {
		t.Fatal("GroupMembers key missing")
	}
	if members == nil {
		t.Error("GroupMembers is null, want []")
	}
}

func TestGroupsList(t *testing.T) {
	h, repo := newTestServer(t)
	alice := seedClient(t, repo, userAliceName)
	if err := repo.AddGroup(t.Context(), &models.Group{
		Name: "devs", ClientIDs: []int64{alice.ID},
	}); err != nil {
		t.Fatalf("add group: %v", err)
	}

	rec := get(t, h, "/groups")
	var groups []api.Group
	if err := json.Unmarshal(rec.Body.Bytes(), &groups); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The admin group, the shared client group, and the devs group.
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3: %+v", len(groups), groups)
	}
}

// Clients must not share a group with the admin: the admin group is the only
// one with write access to the database, so a client in it could rewrite
// another client's access rules.
func TestClientsAreNotInTheAdminGroup(t *testing.T) {
	h, repo := newTestServer(t)
	client := seedClient(t, repo, userAliceName)

	if api.DefaultIDLayout().UserFor(client).Gid != uint(api.DefaultSharedGroupGID) {
		t.Errorf("client primary gid = %d, want the read-only shared gid %d",
			api.DefaultIDLayout().UserFor(client).Gid, uint(api.DefaultSharedGroupGID))
	}
	if uint(api.DefaultSharedGroupGID) == uint(api.DefaultAdminGroupGID) {
		t.Fatal("the client and admin groups must be distinct")
	}

	rec := get(t, h, "/group/gid/"+itoa(uint(api.DefaultAdminGroupGID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin group must resolve, got %d", rec.Code)
	}
	var adminGroup api.Group
	_ = json.Unmarshal(rec.Body.Bytes(), &adminGroup)
	for _, m := range adminGroup.GroupMembers {
		if m == userAliceName {
			t.Errorf("client %q is a member of the admin group", m)
		}
	}
	if len(adminGroup.GroupMembers) != 1 || adminGroup.GroupMembers[0] != api.AdminUser {
		t.Errorf("admin group members = %v, want only %q",
			adminGroup.GroupMembers, api.AdminUser)
	}
}

// The directory must not hand out clients' public keys: sshd gets them from
// "proxpass authorized-keys", and this endpoint is unauthenticated.
func TestDirectoryDoesNotExposeAuthKeys(t *testing.T) {
	h, repo := newTestServer(t)
	// A public key, not a secret.
	const pubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1" +
		"En9yM7XsMUUDyFgiGWn3WZZqfI3JF alice"
	seedClient(t, repo, userAliceName, pubKey)

	rec := get(t, h, "/user/name/"+userAliceName)
	if strings.Contains(rec.Body.String(), "AAAAC3Nza") {
		t.Errorf("the directory leaked a public key: %s", rec.Body.String())
	}
	var user api.User
	_ = json.Unmarshal(rec.Body.Bytes(), &user)
	if len(user.AuthKeys) != 0 {
		t.Errorf("AuthKeys = %v, want empty", user.AuthKeys)
	}
}

func TestUnknownGroupIs404(t *testing.T) {
	h, _ := newTestServer(t)
	if rec := get(t, h, "/group/name/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if rec := get(t, h, "/group/gid/999999"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// The admin login name must agree across the packages that use it: the
// directory publishes the NSS entry, the session grants admin routing, and
// the CLI refuses to create a client with it. A mismatch would either lock
// the admin out or open a privilege-escalation hole.
func TestAdminNameIsConsistent(t *testing.T) {
	if api.AdminUser != session.AdminUser {
		t.Errorf("api.AdminUser = %q but session.AdminUser = %q",
			api.AdminUser, session.AdminUser)
	}
	if api.AdminUser != cli.ReservedAdminName {
		t.Errorf("api.AdminUser = %q but cli.ReservedAdminName = %q",
			api.AdminUser, cli.ReservedAdminName)
	}
}

// Every id proxpass hands out must fit inside a user namespace.
//
// A userns-remapped or rootless Docker daemon maps only the 65536
// subordinate ids from /etc/subuid into the container, so an id above 65535
// does not exist there. sshd accepts the public key and only then fails with
// "setresuid <uid>: Invalid argument", which looks like a broken login rather
// than a configuration limit.
func TestIDsFitInAUserNamespace(t *testing.T) {
	const ceiling = 65535

	if uint(api.DefaultUIDBase-1) > ceiling {
		t.Errorf("AdminUID = %d, must be <= %d", uint(api.DefaultUIDBase-1), ceiling)
	}
	if uint(api.DefaultSharedGroupGID) > ceiling {
		t.Errorf("SharedGroupGID = %d, must be <= %d", uint(api.DefaultSharedGroupGID), ceiling)
	}
	if uint(api.DefaultAdminGroupGID) > ceiling {
		t.Errorf("AdminGroupGID = %d, must be <= %d", uint(api.DefaultAdminGroupGID), ceiling)
	}
	if api.DefaultUIDBase > ceiling {
		t.Errorf("UIDBase = %d, must be <= %d", api.DefaultUIDBase, ceiling)
	}
	if api.DefaultGIDBase > ceiling {
		t.Errorf("GIDBase = %d, must be <= %d", api.DefaultGIDBase, ceiling)
	}

	// And a realistic number of clients and groups must still fit.
	const room = 1000
	if api.DefaultUIDBase+room > ceiling {
		t.Errorf("UIDBase %d leaves room for fewer than %d clients under %d",
			api.DefaultUIDBase, room, ceiling)
	}
	if api.DefaultGIDBase+room > ceiling {
		t.Errorf("GIDBase %d leaves room for fewer than %d groups under %d",
			api.DefaultGIDBase, room, ceiling)
	}

	// The admin id must not collide with the client range, and the two group
	// bases must not overlap the uid range.
	if uint(api.DefaultUIDBase-1) >= api.DefaultUIDBase {
		t.Errorf("AdminUID %d must sit below UIDBase %d", uint(api.DefaultUIDBase-1), api.DefaultUIDBase)
	}
	if uint(api.DefaultSharedGroupGID) >= api.DefaultUIDBase || uint(api.DefaultAdminGroupGID) >= api.DefaultUIDBase {
		t.Errorf("the fixed gids (%d, %d) must sit below UIDBase %d",
			uint(api.DefaultSharedGroupGID), uint(api.DefaultAdminGroupGID), api.DefaultUIDBase)
	}
}

// Real served entries must be in range too, not just the constants.
func TestServedIDsAreInRange(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, userAliceName)

	for _, path := range []string{"/users", "/user/name/" + userAliceName} {
		rec := get(t, h, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
	}

	rec := get(t, h, "/users")
	var users []api.User
	if err := json.Unmarshal(rec.Body.Bytes(), &users); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, u := range users {
		if !api.DefaultIDLayout().InRange(u.Uid) {
			t.Errorf("user %q has out-of-range uid %d", u.User, u.Uid)
		}
		if !api.DefaultIDLayout().InRange(u.Gid) {
			t.Errorf("user %q has out-of-range gid %d", u.User, u.Gid)
		}
	}

	rec = get(t, h, "/groups")
	var groups []api.Group
	if err := json.Unmarshal(rec.Body.Bytes(), &groups); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, g := range groups {
		if !api.DefaultIDLayout().InRange(g.Gid) {
			t.Errorf("group %q has out-of-range gid %d", g.Name, g.Gid)
		}
	}
}

func TestHealthz(t *testing.T) {
	h, _ := newTestServer(t)
	if rec := get(t, h, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func itoa(u uint) string {
	return strconv.FormatUint(uint64(u), 10)
}

// The alias uid must resolve back to a name.
//
// sshd and anything else that formats an owner calls getpwuid(); an
// unanswered uid shows as a bare number. This nearly regressed when the alias
// uid moved below AdminUID, because the handler rejected everything under it.
func TestAliasUIDResolvesByUID(t *testing.T) {
	h, _ := newTestServer(t)
	ids := api.DefaultIDLayout()

	rec := get(t, h, "/user/uid/"+strconv.FormatUint(uint64(ids.AliasUID), 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got api.User
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Uid != ids.AliasUID {
		t.Errorf("uid = %d, want %d", got.Uid, ids.AliasUID)
	}
	if got.Gid != ids.SharedGroupGID {
		t.Errorf("gid = %d, want the shared client gid %d", got.Gid, ids.SharedGroupGID)
	}
	if got.User != api.AliasUser {
		t.Errorf("name = %q, want %q", got.User, api.AliasUser)
	}
}

// The admin uid still resolves, and to the admin rather than an alias.
func TestAdminUIDStillResolvesByUID(t *testing.T) {
	h, _ := newTestServer(t)
	ids := api.DefaultIDLayout()

	rec := get(t, h, "/user/uid/"+strconv.FormatUint(uint64(ids.AdminUID), 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got api.User
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.User != api.AdminUser {
		t.Errorf("name = %q, want %q", got.User, api.AdminUser)
	}
	if got.Gid != ids.AdminGroupGID {
		t.Errorf("gid = %d, want the admin gid %d", got.Gid, ids.AdminGroupGID)
	}
}
