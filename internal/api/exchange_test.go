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

// postWithToken issues a POST carrying a bearer token.
func postWithToken(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, path, http.NoBody)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// exchange mints a token, trades it, and returns the credential.
func exchange(t *testing.T, h http.Handler, repo db.Repository, identity *models.SessionIdentity) api.SessionCredential {
	t.Helper()
	minted := mintToken(t, repo, identity)

	rec := postWithToken(t, h, "/session/exchange", minted)
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var out api.SessionCredential
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func TestExchangeReturnsACredentialAndTheIdentity(t *testing.T) {
	h, repo := newTestServer(t)

	got := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: 7,
	})

	if got.Token == "" {
		t.Fatal("exchange returned an empty credential")
	}
	if got.Identity.IdentityName != userAliceName {
		t.Errorf("IdentityName = %q, want %q", got.Identity.IdentityName, userAliceName)
	}
	if got.Identity.ClientID == nil || *got.Identity.ClientID != 7 {
		t.Errorf("ClientID = %v, want 7", got.Identity.ClientID)
	}
	if !got.ExpiresAt.After(time.Now()) {
		t.Errorf("ExpiresAt is not in the future: %v", got.ExpiresAt)
	}
}

// The credential must NOT be the minted token: the whole point is that the
// thing living in the environment stops working immediately.
func TestExchangeReturnsADifferentTokenThanTheOneSpent(t *testing.T) {
	h, repo := newTestServer(t)
	minted := mintToken(t, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: 1,
	})

	rec := postWithToken(t, h, "/session/exchange", minted)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out api.SessionCredential
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Token == minted {
		t.Fatal("the exchange handed back the minted token itself")
	}
}

// Exchanging consumes the minted token. This is what keeps the environment
// copy worthless a moment after the session starts.
func TestExchangeSpendsTheMintedToken(t *testing.T) {
	h, repo := newTestServer(t)
	minted := mintToken(t, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: 1,
	})

	if rec := postWithToken(t, h, "/session/exchange", minted); rec.Code != http.StatusOK {
		t.Fatalf("first exchange: status = %d, want 200", rec.Code)
	}
	rec := postWithToken(t, h, "/session/exchange", minted)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("second exchange: status = %d, want 401 -- the minted "+
			"token must be spent: %s", rec.Code, rec.Body.String())
	}
}

// Unlike the minted token, the credential is presented over and over.
func TestTheCredentialIsReusable(t *testing.T) {
	h, repo := newTestServer(t)
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: 1,
	})

	for i := range 5 {
		rec := getWithToken(t, h, "/session/identity", cred.Token)
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d: status = %d, want 200 -- the credential "+
				"must not be consumed: %s", i+1, rec.Code, rec.Body.String())
		}
	}
}

// A minted token must not work as a credential: it is only good for the
// exchange. Otherwise the short TTL and single use would be bypassable by
// simply calling a different endpoint.
func TestAMintedTokenIsNotACredential(t *testing.T) {
	h, repo := newTestServer(t)
	minted := mintToken(t, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: 1,
	})

	rec := getWithToken(t, h, "/session/identity", minted)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a minted token was accepted as a "+
			"session credential: %s", rec.Code, rec.Body.String())
	}
}

// And the reverse: a credential cannot be exchanged again.
func TestACredentialCannotBeExchanged(t *testing.T) {
	h, repo := newTestServer(t)
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: 1,
	})

	rec := postWithToken(t, h, "/session/exchange", cred.Token)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a credential was accepted for "+
			"exchange: %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeStopsTheCredentialWorking(t *testing.T) {
	h, repo := newTestServer(t)
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: 1,
	})

	if rec := getWithToken(t, h, "/session/identity", cred.Token); rec.Code != http.StatusOK {
		t.Fatalf("before revoke: status = %d, want 200", rec.Code)
	}
	if rec := postWithToken(t, h, "/session/revoke", cred.Token); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: status = %d, want 204: %s", rec.Code, rec.Body.String())
	}
	rec := getWithToken(t, h, "/session/identity", cred.Token)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("after revoke: status = %d, want 401", rec.Code)
	}
}

// Revoking something already gone is not a failure: a session that died
// early has nothing to give up and must not report an error for it.
func TestRevokeIsIdempotent(t *testing.T) {
	h, repo := newTestServer(t)
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: 1,
	})

	for i := range 3 {
		rec := postWithToken(t, h, "/session/revoke", cred.Token)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("revoke %d: status = %d, want 204", i+1, rec.Code)
		}
	}
}

func TestExchangeWithoutATokenIs401(t *testing.T) {
	h, _ := newTestServer(t)

	if rec := postWithToken(t, h, "/session/exchange", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// One session's credential must not be affected by another's revocation.
func TestRevokingOneCredentialLeavesOthersAlone(t *testing.T) {
	h, repo := newTestServer(t)
	alice := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: 1,
	})
	bob := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: "bob", ClientID: 2,
	})

	if rec := postWithToken(t, h, "/session/revoke", alice.Token); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: status = %d, want 204", rec.Code)
	}
	if rec := getWithToken(t, h, "/session/identity", bob.Token); rec.Code != http.StatusOK {
		t.Fatalf("bob's credential stopped working when alice revoked: %d", rec.Code)
	}
}

// Creating a second credential must not sweep the first: two sessions run at
// once routinely.
func TestExchangingDoesNotInvalidateAnEarlierCredential(t *testing.T) {
	h, repo := newTestServer(t)
	first := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: 1,
	})
	_ = exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: "bob", ClientID: 2,
	})

	if rec := getWithToken(t, h, "/session/identity", first.Token); rec.Code != http.StatusOK {
		t.Fatalf("the first credential stopped working after a second "+
			"exchange: status = %d", rec.Code)
	}
}
