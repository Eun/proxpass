package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"proxpass/internal/api"
	"proxpass/internal/db"
	"proxpass/internal/models"
)

// mintToken stores a token for identity and returns the token itself.
func mintToken(t *testing.T, repo db.Repository, identity *models.SessionIdentity) string {
	t.Helper()
	const token = "test-token-value"
	now := time.Now()
	if err := repo.MintSessionToken(
		t.Context(), api.HashToken(token), identity, now, now.Add(time.Minute)); err != nil {
		t.Fatalf("mint: %v", err)
	}
	return token
}

// getWithToken issues a GET carrying a bearer token.
func getWithToken(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet, path, http.NoBody)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSessionIdentityReturnsTheTokensOwner(t *testing.T) {
	h, repo := newTestServer(t)
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName:    userAliasName,
		IdentityName: userAliceName,
		ClientID:     7,
	})

	rec := getWithToken(t, h, "/session/identity", cred.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got api.Identity
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.LoginName != userAliasName {
		t.Errorf("User = %q, want the login name", got.LoginName)
	}
	if got.IdentityName != userAliceName {
		t.Errorf("IdentityName = %q, want the client's configured name", got.IdentityName)
	}
	if got.IsAdmin {
		t.Error("a client token reported isAdmin")
	}
	if got.ClientID == nil || *got.ClientID != 7 {
		t.Errorf("ClientID = %v, want 7", got.ClientID)
	}
}

// The administrator has no client row, so the field must be absent rather
// than present as 0 -- which would read as "the client with id 0".
func TestAdminIdentityOmitsTheClientID(t *testing.T) {
	h, repo := newTestServer(t)
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName:    "whatever",
		IdentityName: api.AdminUser,
		IsAdmin:      true,
	})

	rec := getWithToken(t, h, "/session/identity", cred.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := raw["clientId"]; present {
		t.Errorf("admin identity carries clientId: %v", raw)
	}
	if raw["isAdmin"] != true {
		t.Errorf("isAdmin = %v, want true", raw["isAdmin"])
	}
}

func TestSessionIdentityWithoutATokenIs401(t *testing.T) {
	h, _ := newTestServer(t)

	rec := getWithToken(t, h, "/session/identity", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rec.Code, rec.Body.String())
	}
}

func TestSessionIdentityWithAnUnknownTokenIs401(t *testing.T) {
	h, _ := newTestServer(t)

	rec := getWithToken(t, h, "/session/identity", "not-a-real-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rec.Code, rec.Body.String())
	}
}

// nss_http sends no Authorization header, and sshd resolves the login
// through NSS before any session exists. Requiring a token on these would
// break every login.
func TestNSSRoutesNeedNoToken(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, userAliceName, "ssh-ed25519 AAAAalice alice")

	for _, path := range []string{
		"/user/name/" + userAliceName, "/users", "/groups", "/group/name/proxpass",
	} {
		if rec := getWithToken(t, h, path, ""); rec.Code != http.StatusOK {
			t.Errorf("%s without a token: status = %d, want 200", path, rec.Code)
		}
	}
}

// The entrypoint polls /healthz before anything has a token, and the spec
// marks it unauthenticated.
func TestHealthzNeedsNoToken(t *testing.T) {
	h, _ := newTestServer(t)

	if rec := getWithToken(t, h, "/healthz", ""); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// A token is only a credential if it cannot be guessed from stored state.
func TestHashTokenIsNotReversibleToTheToken(t *testing.T) {
	const token = "a-token"

	hash := api.HashToken(token)
	if hash == token {
		t.Fatal("HashToken returned its input")
	}
	// Minting and redeeming happen in different processes, so the same
	// token must hash the same way in both.
	if again := api.HashToken(token); again != hash {
		t.Fatalf("HashToken is not deterministic: %q then %q", hash, again)
	}
	if api.HashToken("a") == api.HashToken("b") {
		t.Fatal("HashToken collided on trivially different inputs")
	}
}
