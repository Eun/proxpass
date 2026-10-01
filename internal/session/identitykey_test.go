package session_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/session"
)

// Distinct, valid ed25519 keys.
const (
	keyAdmin  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF admin"
	keyAlice  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHixnSBaUZmAX3Qd4hYl71jjgr58KXAJTdKjFrax6FHN alice"
	keyBob    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOG/T2Snw/38000pfUM6LhVXu4rKZrlrbfHhu7u0Yc3D bob"
	keyNobody = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcSbSQdXYrGFBiCRxY1EM7SPXPdRn1J+VvBR5LgMUSA nobody"
)

// userBob is a second client name, used to prove the key wins over the name.
const userBob = "bob"

// writeAuthInfo creates a file in sshd's SSH_USER_AUTH format and returns
// its path. Each line is "<method> <authorized_keys entry>".
func writeAuthInfo(t *testing.T, keys ...string) string {
	t.Helper()
	var b strings.Builder
	for _, k := range keys {
		b.WriteString("publickey " + k + "\n")
	}
	path := filepath.Join(t.TempDir(), "sshauth")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write auth info: %v", err)
	}
	return path
}

func addNamedClient(t *testing.T, repo db.Repository, name, key string) *models.Client {
	t.Helper()
	c := &models.Client{Name: name, PublicKeys: []string{key}}
	if err := repo.AddClient(t.Context(), c); err != nil {
		t.Fatalf("add client %s: %v", name, err)
	}
	return c
}

// The key decides who you are, whatever name you type.
//
// This is the whole point: a client no longer has to spell its own name out,
// because the name was never what identified it.
func TestKeyIdentifiesTheClientUnderAnyLoginName(t *testing.T) {
	repo := newRepo(t)
	alice := addNamedClient(t, repo, userAlice, keyAlice)

	for _, login := range []string{userAlice, session.AdminUser, userAlias, "whatever"} {
		t.Run(login, func(t *testing.T) {
			id, err := session.ResolveIdentityByKey(
				t.Context(), repo, login, writeAuthInfo(t, keyAlice), keyAdmin)
			if err != nil {
				t.Fatalf("ResolveIdentityByKey: %v", err)
			}
			if id.IsAdmin {
				t.Error("alice's key must never grant admin")
			}
			if id.ClientID != alice.ID {
				t.Errorf("ClientID = %d, want %d", id.ClientID, alice.ID)
			}
			if id.DisplayName != userAlice {
				t.Errorf("DisplayName = %q, want %q", id.DisplayName, userAlice)
			}
			// The login name is still carried for the log.
			if id.User != login {
				t.Errorf("User = %q, want the name as given %q", id.User, login)
			}
		})
	}
}

// The same rule applies to the administrator: the key grants admin, the name
// does not.
func TestKeyIdentifiesTheAdminUnderAnyLoginName(t *testing.T) {
	repo := newRepo(t)
	addNamedClient(t, repo, userAlice, keyAlice)

	for _, login := range []string{session.AdminUser, userAlice, userAlias} {
		t.Run(login, func(t *testing.T) {
			id, err := session.ResolveIdentityByKey(
				t.Context(), repo, login, writeAuthInfo(t, keyAdmin), keyAdmin)
			if err != nil {
				t.Fatalf("ResolveIdentityByKey: %v", err)
			}
			if !id.IsAdmin {
				t.Error("the admin key must grant admin whatever the name")
			}
			if id.DisplayName != session.AdminUser {
				t.Errorf("DisplayName = %q, want %q", id.DisplayName, session.AdminUser)
			}
		})
	}
}

// An admin key stored in the database works the same as one passed by flag.
func TestAdminKeyFromTheDatabaseIsAccepted(t *testing.T) {
	repo := newRepo(t)
	if err := repo.AddAdminKey(t.Context(), keyAdmin); err != nil {
		t.Fatalf("add admin key: %v", err)
	}
	id, err := session.ResolveIdentityByKey(
		t.Context(), repo, "whatever", writeAuthInfo(t, keyAdmin), "")
	if err != nil {
		t.Fatalf("ResolveIdentityByKey: %v", err)
	}
	if !id.IsAdmin {
		t.Error("a stored admin key must grant admin")
	}
}

// A key nobody owns must be refused outright.
//
// Falling back to the login name would mean anyone holding any key sshd
// still accepts could choose who to be, which is the escalation this design
// exists to prevent.
func TestUnknownKeyIsRefused(t *testing.T) {
	repo := newRepo(t)
	addNamedClient(t, repo, userAlice, keyAlice)

	for _, login := range []string{session.AdminUser, userAlice, userAlias} {
		t.Run(login, func(t *testing.T) {
			_, err := session.ResolveIdentityByKey(
				t.Context(), repo, login, writeAuthInfo(t, keyNobody), keyAdmin)
			if !errors.Is(err, session.ErrUnknownKey) {
				t.Errorf("err = %v, want ErrUnknownKey", err)
			}
		})
	}
}

// Without SSH_USER_AUTH the session cannot know the key, so it must refuse
// rather than trust the name.
func TestMissingAuthInfoIsRefused(t *testing.T) {
	repo := newRepo(t)
	addNamedClient(t, repo, userAlice, keyAlice)

	_, err := session.ResolveIdentityByKey(
		t.Context(), repo, userAlice, "", keyAdmin)
	if !errors.Is(err, session.ErrNoAuthInfo) {
		t.Errorf("err = %v, want ErrNoAuthInfo", err)
	}
}

// A missing or unreadable auth-info file must also fail closed.
func TestUnreadableAuthInfoIsRefused(t *testing.T) {
	repo := newRepo(t)
	_, err := session.ResolveIdentityByKey(
		t.Context(), repo, userAlice,
		filepath.Join(t.TempDir(), "does-not-exist"), keyAdmin)
	if err == nil {
		t.Error("an unreadable auth-info file must be refused")
	}
	// It must NOT be mistaken for a successful resolution.
	if errors.Is(err, nil) {
		t.Error("expected a real error")
	}
}

// An auth-info file recording a non-publickey method yields no key, so the
// session has nothing to identify and must refuse.
func TestNonPublicKeyAuthIsRefused(t *testing.T) {
	repo := newRepo(t)
	path := filepath.Join(t.TempDir(), "sshauth")
	if err := os.WriteFile(path, []byte("password\nkeyboard-interactive\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := session.ResolveIdentityByKey(t.Context(), repo, userAlice, path, keyAdmin)
	if !errors.Is(err, session.ErrUnknownKey) {
		t.Errorf("err = %v, want ErrUnknownKey", err)
	}
}

// A key registered to two different clients does not name one identity, so
// it must be refused rather than resolved to whichever row came first.
func TestKeySharedBetweenClientsIsRefused(t *testing.T) {
	repo := newRepo(t)
	addNamedClient(t, repo, userAlice, keyAlice)
	addNamedClient(t, repo, userBob, keyAlice) // same key, different client

	_, err := session.ResolveIdentityByKey(
		t.Context(), repo, "whatever", writeAuthInfo(t, keyAlice), keyAdmin)
	if !errors.Is(err, session.ErrDuplicateKey) {
		t.Errorf("err = %v, want ErrDuplicateKey", err)
	}
}

// A key that is both an admin key and a client's is ambiguous in the most
// dangerous direction, so it must be refused rather than silently granting
// admin.
func TestKeyThatIsBothAdminAndClientIsRefused(t *testing.T) {
	repo := newRepo(t)
	addNamedClient(t, repo, userAlice, keyAlice)

	_, err := session.ResolveIdentityByKey(
		t.Context(), repo, "whatever", writeAuthInfo(t, keyAlice), keyAlice)
	if !errors.Is(err, session.ErrDuplicateKey) {
		t.Errorf("err = %v, want ErrDuplicateKey", err)
	}
}

// The same key listed twice for ONE identity is not a conflict: it still
// names a single client.
func TestDuplicateKeyWithinOneClientIsFine(t *testing.T) {
	repo := newRepo(t)
	c := &models.Client{Name: userAlice, PublicKeys: []string{keyAlice, keyAlice}}
	if err := repo.AddClient(t.Context(), c); err != nil {
		t.Fatalf("add client: %v", err)
	}

	id, err := session.ResolveIdentityByKey(
		t.Context(), repo, "whatever", writeAuthInfo(t, keyAlice), keyAdmin)
	if err != nil {
		t.Fatalf("ResolveIdentityByKey: %v", err)
	}
	if id.ClientID != c.ID {
		t.Errorf("ClientID = %d, want %d", id.ClientID, c.ID)
	}
}

// An admin key appearing both in --admin-key and the database is likewise
// one identity.
func TestAdminKeyInBothFlagAndDatabaseIsFine(t *testing.T) {
	repo := newRepo(t)
	if err := repo.AddAdminKey(t.Context(), keyAdmin); err != nil {
		t.Fatalf("add admin key: %v", err)
	}
	id, err := session.ResolveIdentityByKey(
		t.Context(), repo, "whatever", writeAuthInfo(t, keyAdmin), keyAdmin)
	if err != nil {
		t.Fatalf("ResolveIdentityByKey: %v", err)
	}
	if !id.IsAdmin {
		t.Error("want admin")
	}
}

// Two clients with different keys must each resolve to themselves.
func TestDistinctKeysResolveToTheirOwners(t *testing.T) {
	repo := newRepo(t)
	alice := addNamedClient(t, repo, userAlice, keyAlice)
	bob := addNamedClient(t, repo, userBob, keyBob)

	for _, tc := range []struct {
		key  string
		want int64
		name string
	}{
		{keyAlice, alice.ID, userAlice},
		{keyBob, bob.ID, userBob},
	} {
		// Deliberately log in under the OTHER client's name: the key wins.
		other := userBob
		if tc.name == userBob {
			other = userAlice
		}
		id, err := session.ResolveIdentityByKey(
			t.Context(), repo, other, writeAuthInfo(t, tc.key), keyAdmin)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if id.ClientID != tc.want {
			t.Errorf("key %s under login %q resolved to client %d, want %d (%s)",
				tc.name, other, id.ClientID, tc.want, tc.name)
		}
		if id.DisplayName != tc.name {
			t.Errorf("DisplayName = %q, want %q", id.DisplayName, tc.name)
		}
	}
}

// The error must name the key so an operator can tell which one was refused.
func TestUnknownKeyErrorNamesTheKey(t *testing.T) {
	repo := newRepo(t)
	_, err := session.ResolveIdentityByKey(
		t.Context(), repo, "x", writeAuthInfo(t, keyNobody), "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "SHA256:") {
		t.Errorf("error does not include a fingerprint: %v", err)
	}
}
