package api

// Internal (package api) tests so the admin handlers can be called directly
// with a bearer token on the context, which is what callerIdentity reads.
// The context key is unexported, so this cannot live in package api_test; the
// point of calling the methods directly rather than over HTTP is to test the
// handler logic without the router in the way.

import (
	"context"
	"io"
	"log"
	"testing"
	"time"

	"proxpass/internal/db"
	"proxpass/internal/models"
)

// Shared fixture strings, named so goconst does not flag their repetition.
const (
	testAdminKey    = "ssh-ed25519 AAAA admin"
	testEndpoint    = "proxpass.example"
	testClientAlice = "alice"
)

// newAdminHandler returns a handler over a fresh in-memory repo plus a
// context carrying an administrator credential, so a handler sees IsAdmin.
func newAdminHandler(t *testing.T) (*SessionHandler, db.Repository, context.Context) {
	t.Helper()
	repo, err := db.NewSQLiteRepository(t.TempDir() + "/admin.db")
	if err != nil {
		t.Fatalf("open repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	h := NewSessionHandler(repo, log.New(io.Discard, "", 0))

	const token = "admin-credential" //nolint:gosec // G101: fake test credential, not a secret
	now := time.Now()
	identity := &models.SessionIdentity{
		LoginName:    AdminUser,
		IdentityName: AdminUser,
		IsAdmin:      true,
	}
	if err := repo.CreateAPISession(
		t.Context(), HashToken(token), identity, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("create api session: %v", err)
	}
	ctx := context.WithValue(t.Context(), bearerTokenKey, token)
	return h, repo, ctx
}

// clientCtx returns a context carrying a non-admin (client) credential, used
// to assert the admin check refuses an ordinary caller.
func clientCtx(t *testing.T, repo db.Repository) context.Context {
	t.Helper()
	const token = "client-credential"
	now := time.Now()
	identity := &models.SessionIdentity{
		LoginName:    testClientAlice,
		IdentityName: testClientAlice,
		ClientID:     1,
	}
	if err := repo.CreateAPISession(
		t.Context(), HashToken(token), identity, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("create client api session: %v", err)
	}
	return context.WithValue(t.Context(), bearerTokenKey, token)
}

// The happy path: an instance added through AddInstance comes back from
// ListInstances and GetInstance, carrying every field including the secrets.
func TestAddInstanceRoundTrips(t *testing.T) {
	h, _, ctx := newAdminHandler(t)

	body := AddInstanceJSONRequestBody{
		Name:             "pve",
		APIURL:           "https://pve:8006",
		APITokenID:       "root@pam!tok",
		APITokenSecret:   "secret",
		ConsoleTransport: ProxmoxInstanceConsoleTransportTermproxy,
		Node:             "pve1",
		InsecureTLS:      true,
		InsecureSSH:      true,
		SSHHost:          "pve.example",
		SSHPort:          2222,
		SSHUser:          "root",
		SSHFingerprints:  []string{"SHA256:abc"},
	}
	resp, err := h.AddInstance(ctx, AddInstanceRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("AddInstance: %v", err)
	}
	created, ok := resp.(AddInstance201JSONResponse)
	if !ok {
		t.Fatalf("AddInstance returned %T, want 201", resp)
	}
	if created.ID == 0 {
		t.Fatal("AddInstance did not assign an id")
	}
	if len(created.SSHFingerprints) != 1 || created.SSHFingerprints[0] != "SHA256:abc" || created.SSHPort != 2222 ||
		!created.InsecureSSH || !created.InsecureTLS {
		t.Errorf("AddInstance dropped a field: %+v", created)
	}

	listResp, err := h.ListInstances(ctx, ListInstancesRequestObject{})
	if err != nil {
		t.Fatalf("ListInstances: %v", err)
	}
	list, ok := listResp.(ListInstances200JSONResponse)
	if !ok {
		t.Fatalf("ListInstances returned %T, want 200", listResp)
	}
	if len(list) != 1 || list[0].Name != "pve" {
		t.Fatalf("ListInstances = %+v, want one named pve", list)
	}

	getResp, err := h.GetInstance(ctx, GetInstanceRequestObject{ID: created.ID})
	if err != nil {
		t.Fatalf("GetInstance: %v", err)
	}
	got, ok := getResp.(GetInstance200JSONResponse)
	if !ok {
		t.Fatalf("GetInstance returned %T, want 200", getResp)
	}
	if got.APITokenSecret != "secret" {
		t.Errorf("GetInstance secret = %q, want the stored one", got.APITokenSecret)
	}
}

// Adding the same client name twice is a 409, not a 500: the second add hits
// the UNIQUE(name) constraint, which the handler classifies as a conflict.
func TestAddClientDuplicateIs409(t *testing.T) {
	h, _, ctx := newAdminHandler(t)

	body := AddClientJSONRequestBody{Name: "dup", PublicKeys: []string{"ssh-ed25519 AAAA x"}}
	if _, err := h.AddClient(ctx, AddClientRequestObject{Body: &body}); err != nil {
		t.Fatalf("first AddClient: %v", err)
	}

	again := AddClientJSONRequestBody{Name: "dup"}
	resp, err := h.AddClient(ctx, AddClientRequestObject{Body: &again})
	if err != nil {
		t.Fatalf("second AddClient returned a hard error, want a 409 response: %v", err)
	}
	if _, ok := resp.(AddClient409JSONResponse); !ok {
		t.Fatalf("second AddClient returned %T, want AddClient409JSONResponse", resp)
	}
}

// Getting an instance that does not exist is a 404.
func TestGetMissingInstanceIs404(t *testing.T) {
	h, _, ctx := newAdminHandler(t)

	resp, err := h.GetInstance(ctx, GetInstanceRequestObject{ID: 9999})
	if err != nil {
		t.Fatalf("GetInstance returned a hard error, want a 404 response: %v", err)
	}
	if _, ok := resp.(GetInstance404JSONResponse); !ok {
		t.Fatalf("GetInstance returned %T, want GetInstance404JSONResponse", resp)
	}
}

// A grant dispatches on the subject kind: a client grant becomes an access
// rule of type client, visible through ListAccessRules.
func TestGrantAccessByClientKind(t *testing.T) {
	h, repo, ctx := newAdminHandler(t)

	client := &models.Client{Name: testClientAlice}
	if err := repo.AddClient(t.Context(), client); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	stored, err := repo.GetClientByName(t.Context(), testClientAlice)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}

	body := GrantAccessJSONRequestBody{
		Subject:  AccessSubject{Kind: RuleTypeClient, ID: stored.ID},
		GuestIds: []int64{1, 2},
	}
	resp, err := h.GrantAccess(ctx, GrantAccessRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("GrantAccess: %v", err)
	}
	if _, ok := resp.(GrantAccess204Response); !ok {
		t.Fatalf("GrantAccess returned %T, want 204", resp)
	}

	rulesResp, err := h.ListAccessRules(ctx, ListAccessRulesRequestObject{})
	if err != nil {
		t.Fatalf("ListAccessRules: %v", err)
	}
	rules, ok := rulesResp.(ListAccessRules200JSONResponse)
	if !ok {
		t.Fatalf("ListAccessRules returned %T, want 200", rulesResp)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	for _, r := range rules {
		if r.Type != RuleTypeClient || r.SubjectID != stored.ID {
			t.Errorf("rule = %+v, want a client rule for the seeded client", r)
		}
	}
}

// An unknown subject kind is a 400, not a silent success.
func TestGrantAccessUnknownKindIs400(t *testing.T) {
	h, _, ctx := newAdminHandler(t)

	body := GrantAccessJSONRequestBody{
		Subject:  AccessSubject{Kind: RuleType("nonsense"), ID: 1},
		GuestIds: []int64{1},
	}
	resp, err := h.GrantAccess(ctx, GrantAccessRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("GrantAccess returned a hard error, want a 400: %v", err)
	}
	if _, ok := resp.(GrantAccess400JSONResponse); !ok {
		t.Fatalf("GrantAccess returned %T, want GrantAccess400JSONResponse", resp)
	}
}

// Settings round-trip through SetSetting/GetSetting.
func TestSettingRoundTrips(t *testing.T) {
	h, _, ctx := newAdminHandler(t)

	setBody := SetSettingJSONRequestBody{Value: testEndpoint}
	setResp, err := h.SetSetting(ctx, SetSettingRequestObject{
		Key: db.SettingPublicEndpoint, Body: &setBody})
	if err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	set, ok := setResp.(SetSetting200JSONResponse)
	if !ok {
		t.Fatalf("SetSetting returned %T, want 200", setResp)
	}
	if set.Key != db.SettingPublicEndpoint || set.Value != testEndpoint {
		t.Fatalf("SetSetting = %+v, want the stored key/value", set)
	}

	getResp, err := h.GetSetting(ctx, GetSettingRequestObject{Key: db.SettingPublicEndpoint})
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	got, ok := getResp.(GetSetting200JSONResponse)
	if !ok {
		t.Fatalf("GetSetting returned %T, want 200", getResp)
	}
	if got.Value != testEndpoint {
		t.Errorf("GetSetting value = %q, want the stored one", got.Value)
	}
}

// Admin keys list/add/remove round-trip; the list serializes as a non-nil
// slice even when empty.
func TestAdminKeyRoundTrips(t *testing.T) {
	h, _, ctx := newAdminHandler(t)

	addBody := AddAdminKeyJSONRequestBody{PublicKey: testAdminKey}
	if _, err := h.AddAdminKey(ctx, AddAdminKeyRequestObject{Body: &addBody}); err != nil {
		t.Fatalf("AddAdminKey: %v", err)
	}

	listResp, err := h.ListAdminKeys(ctx, ListAdminKeysRequestObject{})
	if err != nil {
		t.Fatalf("ListAdminKeys: %v", err)
	}
	list, ok := listResp.(ListAdminKeys200JSONResponse)
	if !ok {
		t.Fatalf("ListAdminKeys returned %T, want 200", listResp)
	}
	if len(list.PublicKeys) != 1 || list.PublicKeys[0] != testAdminKey {
		t.Fatalf("ListAdminKeys = %+v, want the one added", list)
	}

	rmBody := RemoveAdminKeyJSONRequestBody{PublicKey: testAdminKey}
	rmResp, err := h.RemoveAdminKey(ctx, RemoveAdminKeyRequestObject{Body: &rmBody})
	if err != nil {
		t.Fatalf("RemoveAdminKey: %v", err)
	}
	if _, ok := rmResp.(RemoveAdminKey204Response); !ok {
		t.Fatalf("RemoveAdminKey returned %T, want 204", rmResp)
	}
}

// The configured admin key (PROXPASS_ADMIN_KEY) is refused for removal with a
// 409, so a UI delete cannot lock the configured administrator out. A
// different key is still removable.
func TestRemoveAdminKeyRefusesTheProtectedKey(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	h.WithProtectedAdminKey("  " + testAdminKey + "  ") // whitespace must not defeat the guard

	for _, k := range []string{testAdminKey, "ssh-ed25519 AAAA other"} {
		body := AddAdminKeyJSONRequestBody{PublicKey: k}
		if _, err := h.AddAdminKey(ctx, AddAdminKeyRequestObject{Body: &body}); err != nil {
			t.Fatalf("AddAdminKey(%q): %v", k, err)
		}
	}

	// The protected key is refused with a 409.
	rmProtected := RemoveAdminKeyJSONRequestBody{PublicKey: testAdminKey}
	resp, err := h.RemoveAdminKey(ctx, RemoveAdminKeyRequestObject{Body: &rmProtected})
	if err != nil {
		t.Fatalf("RemoveAdminKey(protected): %v", err)
	}
	if _, ok := resp.(RemoveAdminKey409JSONResponse); !ok {
		t.Fatalf("RemoveAdminKey(protected) returned %T, want 409", resp)
	}

	// A different key is still removable.
	rmOther := RemoveAdminKeyJSONRequestBody{PublicKey: "ssh-ed25519 AAAA other"}
	resp, err = h.RemoveAdminKey(ctx, RemoveAdminKeyRequestObject{Body: &rmOther})
	if err != nil {
		t.Fatalf("RemoveAdminKey(other): %v", err)
	}
	if _, ok := resp.(RemoveAdminKey204Response); !ok {
		t.Fatalf("RemoveAdminKey(other) returned %T, want 204", resp)
	}
}

// A non-admin credential is refused with a 403 even though the credential is
// otherwise valid.
func TestAdminEndpointRefusesANonAdmin(t *testing.T) {
	h, repo, _ := newAdminHandler(t)
	ctx := clientCtx(t, repo)

	resp, err := h.ListInstances(ctx, ListInstancesRequestObject{})
	if err != nil {
		t.Fatalf("ListInstances returned a hard error, want a 403: %v", err)
	}
	if _, ok := resp.(ListInstances403JSONResponse); !ok {
		t.Fatalf("ListInstances returned %T, want ListInstances403JSONResponse", resp)
	}
}

// With no credential on the context the handler answers 401.
func TestAdminEndpointNeedsACredential(t *testing.T) {
	h, _, _ := newAdminHandler(t)

	resp, err := h.ListInstances(t.Context(), ListInstancesRequestObject{})
	if err != nil {
		t.Fatalf("ListInstances returned a hard error, want a 401: %v", err)
	}
	if _, ok := resp.(ListInstances401JSONResponse); !ok {
		t.Fatalf("ListInstances returned %T, want ListInstances401JSONResponse", resp)
	}
}

// RunDiscovery without a wired discoverer fails loudly rather than panicking.
func TestRunDiscoveryWithoutADiscovererErrors(t *testing.T) {
	h, _, ctx := newAdminHandler(t)

	if _, err := h.RunDiscovery(ctx, RunDiscoveryRequestObject{}); err == nil {
		t.Fatal("RunDiscovery with no discoverer returned nil error, want a clear failure")
	}
}
