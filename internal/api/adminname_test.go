package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"proxpass/internal/api"
	"proxpass/internal/models"
)

// The reserved admin name is recognized whatever its case.
//
// Four places test a login name against "admin": isReservedLoginName, the
// IsLoginNameReserved endpoint, ValidateClientName, and the directory lookup
// here. The first three have always used EqualFold; this one used ==, so
// "ADMIN" was reserved everywhere EXCEPT where its directory entry was
// chosen, and was served from the shared alias pool instead.
//
// Nothing is granted by the entry either way -- authority comes from the key
// that authenticated, and the admin gid has conferred nothing since the
// database became 0600 inside a 2700 directory. What the entry decides is
// the uid, and aliases deliberately SHARE one: IDLayout.AliasUID says an
// alias session must not be mistaken for the administrator by anything
// keying off process ownership. Serving the reserved name from that pool was
// exactly that mistake.
func TestTheAdminNameIsServedWhateverItsCase(t *testing.T) {
	h, _ := newTestServer(t)
	ids := api.DefaultIDLayout()

	for _, name := range []string{"admin", "ADMIN", "Admin", "aDmIn"} {
		rec := get(t, h, "/user/name/"+name)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", name, rec.Code)
			continue
		}
		var user api.User
		if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil {
			t.Errorf("%s: decode: %v", name, err)
			continue
		}
		if user.Uid != ids.AdminUID {
			t.Errorf("%s: uid = %d, want the admin uid %d -- the reserved "+
				"name was served from the shared alias pool",
				name, user.Uid, ids.AdminUID)
		}
		if user.Uid == ids.AliasUID {
			t.Errorf("%s: served the shared alias uid %d", name, user.Uid)
		}
		// The entry echoes the name as typed, so the session's own files
		// are owned by something `ls -l' can name.
		if user.User != name {
			t.Errorf("%s: User = %q, want the name as given", name, user.User)
		}
	}
}

// A name that merely contains "admin" is NOT the reserved one: the match is
// case-insensitive, not fuzzy.
func TestOnlyTheExactAdminNameIsReserved(t *testing.T) {
	h, _ := newTestServer(t)
	ids := api.DefaultIDLayout()

	for _, name := range []string{"admins", "administrator", "notadmin", "ad-min"} {
		rec := get(t, h, "/user/name/"+name)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200 (served as an alias)", name, rec.Code)
			continue
		}
		var user api.User
		if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil {
			t.Errorf("%s: decode: %v", name, err)
			continue
		}
		if user.Uid != ids.AliasUID {
			t.Errorf("%s: uid = %d, want the alias uid %d: only %q itself "+
				"is reserved", name, user.Uid, ids.AliasUID, api.AdminUser)
		}
	}
}

// Group names resolve case-insensitively too, matching the user lookup.
func TestGroupByNameIsCaseInsensitive(t *testing.T) {
	h, repo := newTestServer(t)
	if err := repo.AddGroup(t.Context(), &models.Group{Name: "ops", ClientIDs: []int64{}}); err != nil {
		t.Fatalf("add group: %v", err)
	}

	for _, name := range []string{"ops", "OPS", "Ops"} {
		rec := get(t, h, "/group/name/"+name)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", name, rec.Code)
		}
	}
}
