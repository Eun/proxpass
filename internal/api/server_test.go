package api_test

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"proxpass/internal/api"
	"proxpass/internal/db"
	"proxpass/internal/models"
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

func TestUserByName(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, "alice", "ssh-ed25519 AAAAkey alice")

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
	if user.Uid < api.UIDBase {
		t.Errorf("Uid = %d, want >= %d to avoid colliding with system users",
			user.Uid, api.UIDBase)
	}
	if user.Shell == "" || user.Dir == "" {
		t.Errorf("Shell/Dir must be set, got %q/%q", user.Shell, user.Dir)
	}
}

// The capitalized JSON keys are the nss_http wire format. Lowercasing them
// would make every NSS lookup silently return an empty entry.
func TestUserJSONKeysAreCapitalized(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, "alice", "ssh-ed25519 AAAAkey alice")

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

func TestUnknownUserIs404(t *testing.T) {
	h, _ := newTestServer(t)
	if rec := get(t, h, "/user/name/nobody"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestUserByUID(t *testing.T) {
	h, repo := newTestServer(t)
	client := seedClient(t, repo, "alice", "ssh-ed25519 AAAAkey alice")
	want := api.UserFor(client)

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
	seedClient(t, repo, "alice")

	if rec := get(t, h, "/user/uid/0"); rec.Code != http.StatusNotFound {
		t.Errorf("uid 0: status = %d, want 404", rec.Code)
	}
}

func TestUsersList(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, "alice")
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
	client := seedClient(t, repo, "alice")

	if api.UserFor(client).Uid == api.AdminUID {
		t.Errorf("client uid %d collides with the admin uid", api.AdminUID)
	}
	if rec := get(t, h, "/user/uid/"+itoa(api.AdminUID)); rec.Code != http.StatusOK {
		t.Errorf("admin uid must resolve, got %d", rec.Code)
	}
}

// Every user's primary gid must resolve to a real group, otherwise sshd
// cannot complete the login. All logins share one primary group, because
// supplementary groups would require NSS enumeration (which is disabled).
func TestEveryUserHasAPrimaryGroup(t *testing.T) {
	h, repo := newTestServer(t)
	client := seedClient(t, repo, "alice")
	user := api.UserFor(client)

	if user.Gid != api.SharedGroupGID {
		t.Errorf("primary gid = %d, want the shared gid %d", user.Gid, api.SharedGroupGID)
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
	alice := seedClient(t, repo, "alice")
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
	if group.Gid < api.GIDBase {
		t.Errorf("Gid = %d, want >= %d", group.Gid, api.GIDBase)
	}
}

// GroupMembers must serialize as [] rather than null: nss_http expects a
// list, and a null would be indistinguishable from a decode failure.
func TestEmptyGroupMembersSerializeAsArray(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, "alice")

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
	alice := seedClient(t, repo, "alice")
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
	// The shared primary group plus the devs group.
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2: %+v", len(groups), groups)
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
