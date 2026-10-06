package api_test

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"proxpass/internal/api"
	"proxpass/internal/db"
)

// envLookup builds a lookup function over a fixed map, standing in for
// os.LookupEnv.
func envLookup(vars map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
	}
}

// With nothing set the built-in layout applies, and it must be usable on a
// user-namespaced daemon.
func TestLoadIDLayoutDefaults(t *testing.T) {
	l, err := api.LoadIDLayout(envLookup(nil))
	if err != nil {
		t.Fatalf("defaults must be valid: %v", err)
	}
	if l.AdminUID != api.DefaultUIDBase-1 {
		t.Errorf("AdminUID = %d, want %d", l.AdminUID, api.DefaultUIDBase-1)
	}
	if l.MaxID != api.DefaultMaxID {
		t.Errorf("MaxID = %d, want %d", l.MaxID, api.DefaultMaxID)
	}
	for name, id := range map[string]uint{
		"AdminUID":       l.AdminUID,
		"AdminGroupGID":  l.AdminGroupGID,
		"AliasUID":       l.AliasUID,
		"SharedGroupGID": l.SharedGroupGID,
		"UIDBase":        l.UIDBase,
		"GIDBase":        l.GIDBase,
	} {
		if id > l.MaxID {
			t.Errorf("%s = %d exceeds MaxID %d", name, id, l.MaxID)
		}
	}
}

// The point of the type: a deployment can move the whole layout.
func TestLoadIDLayoutOverrides(t *testing.T) {
	l, err := api.LoadIDLayout(envLookup(map[string]string{
		api.EnvAdminUID:       "5000",
		api.EnvAliasUID:       "4999",
		api.EnvAdminGroupGID:  "4001",
		api.EnvSharedGroupGID: "4000",
		api.EnvUIDBase:        "6000",
		api.EnvGIDBase:        "8000",
		api.EnvMaxID:          "9999",
	}))
	if err != nil {
		t.Fatalf("LoadIDLayout: %v", err)
	}
	if l.AdminUID != 5000 || l.UIDBase != 6000 || l.GIDBase != 8000 || l.MaxID != 9999 {
		t.Errorf("overrides not applied: %+v", l)
	}
	if got := l.UIDFor(3); got != 6003 {
		t.Errorf("UIDFor(3) = %d, want 6003", got)
	}
	if got := l.GIDFor(7); got != 8007 {
		t.Errorf("GIDFor(7) = %d, want 8007", got)
	}
}

// An invalid layout must be refused at startup, not produce logins that fail
// after the key has already been accepted.
func TestLoadIDLayoutRejectsInvalid(t *testing.T) {
	cases := map[string]map[string]string{
		"uid above the ceiling": {
			api.EnvUIDBase: "70000",
		},
		"admin uid above the ceiling": {
			api.EnvAdminUID: "99999",
		},
		"admin uid inside the client range": {
			api.EnvAdminUID: "20001",
		},
		"fixed gid inside the derived group range": {
			api.EnvSharedGroupGID: "40001",
		},
		"admin and client groups identical": {
			api.EnvAdminGroupGID:  "19000",
			api.EnvSharedGroupGID: "19000",
		},
		"system range": {
			api.EnvUIDBase: "500",
		},
		"no room for clients": {
			api.EnvUIDBase: "20000",
			api.EnvMaxID:   "20050",
		},
		"not a number": {
			api.EnvUIDBase: "banana",
		},
		"negative": {
			api.EnvUIDBase: "-1",
		},
	}
	for what, vars := range cases {
		t.Run(what, func(t *testing.T) {
			if _, err := api.LoadIDLayout(envLookup(vars)); err == nil {
				t.Errorf("layout %v must be rejected", vars)
			}
		})
	}
}

// The error must name the variable so an operator can act on it.
func TestLoadIDLayoutErrorNamesTheVariable(t *testing.T) {
	_, err := api.LoadIDLayout(envLookup(map[string]string{
		api.EnvUIDBase: "70000",
	}))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), api.EnvUIDBase) {
		t.Errorf("error %q does not mention %s", err, api.EnvUIDBase)
	}
}

// A server built with a custom layout must actually serve those ids.
func TestServerHonoursACustomLayout(t *testing.T) {
	custom := api.IDLayout{
		AdminUID:       5000,
		AliasUID:       4999,
		AdminGroupGID:  4001,
		SharedGroupGID: 4000,
		UIDBase:        6000,
		GIDBase:        8000,
		MaxID:          9999,
	}
	if err := custom.Validate(); err != nil {
		t.Fatalf("test layout is invalid: %v", err)
	}

	repo, err := db.NewSQLiteRepository(t.TempDir() + "/custom.db")
	if err != nil {
		t.Fatalf("open repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	client := seedClient(t, repo, "alice")
	h := api.NewServerWithIDs(repo, log.New(io.Discard, "", 0), custom).Handler()

	rec := get(t, h, "/user/name/alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var user api.User
	_ = json.Unmarshal(rec.Body.Bytes(), &user)

	if want := custom.UIDFor(client.ID); user.Uid != want {
		t.Errorf("Uid = %d, want %d from the custom layout", user.Uid, want)
	}
	if user.Gid != custom.SharedGroupGID {
		t.Errorf("Gid = %d, want the custom shared gid %d", user.Gid, custom.SharedGroupGID)
	}

	// The admin entry follows the custom layout too.
	rec = get(t, h, "/user/name/"+api.AdminUser)
	_ = json.Unmarshal(rec.Body.Bytes(), &user)
	if user.Uid != custom.AdminUID {
		t.Errorf("admin Uid = %d, want %d", user.Uid, custom.AdminUID)
	}
	if user.Gid != custom.AdminGroupGID {
		t.Errorf("admin Gid = %d, want %d", user.Gid, custom.AdminGroupGID)
	}

	// And the groups are published at the custom gids.
	if rec := get(t, h, "/group/gid/4000"); rec.Code != http.StatusOK {
		t.Errorf("custom shared gid must resolve, got %d", rec.Code)
	}
	if rec := get(t, h, "/group/gid/4001"); rec.Code != http.StatusOK {
		t.Errorf("custom admin gid must resolve, got %d", rec.Code)
	}
}

// An alias is reachable with ANY valid key, including a client's. If it
// shared the administrator's uid then an alias session and an admin session
// would be the same Unix identity, and anything that tells sessions apart by
// their owner -- process ownership now, a per-session credential later --
// could not distinguish them.
func TestAliasUIDDiffersFromTheAdminUID(t *testing.T) {
	l := api.DefaultIDLayout()
	if l.AliasUID == l.AdminUID {
		t.Errorf("AliasUID and AdminUID are both %d", l.AliasUID)
	}
	if err := l.Validate(); err != nil {
		t.Errorf("the default layout must be valid: %v", err)
	}
}

// ...and a layout that collides them is rejected rather than quietly
// restoring the behavior this change removes.
func TestValidateRejectsAnAliasUIDEqualToTheAdminUID(t *testing.T) {
	l := api.DefaultIDLayout()
	l.AliasUID = l.AdminUID
	err := l.Validate()
	if err == nil {
		t.Fatal("Validate accepted an alias uid equal to the admin uid")
	}
	if !strings.Contains(err.Error(), api.EnvAliasUID) {
		t.Errorf("the error should name %s: %v", api.EnvAliasUID, err)
	}
}

// Both fixed uids must stay below the client range, or a client row would
// derive the same uid as the admin or an alias.
func TestValidateRejectsAnAliasUIDInsideTheClientRange(t *testing.T) {
	l := api.DefaultIDLayout()
	l.AliasUID = l.UIDBase
	if err := l.Validate(); err == nil {
		t.Error("Validate accepted an alias uid inside the client range")
	}
}
