package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"proxpass/internal/api"
	"proxpass/internal/db"
	"proxpass/internal/models"
)

// seedInstance adds a Proxmox instance carrying secrets, so that a test can
// assert they do not leak.
func seedInstance(t *testing.T, repo db.Repository, name string) *models.ProxmoxInstance {
	t.Helper()
	inst := &models.ProxmoxInstance{
		Name:           name,
		APIURL:         "https://" + name + ":8006",
		APITokenID:     "root@pam!tok",
		APITokenSecret: secretTokenValue,
		ConnectionType: models.ConnectionTypeTermProxy,
		Node:           "pve1",
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance %q: %v", name, err)
	}
	return inst
}

func seedGuest(t *testing.T, repo db.Repository, instanceID int64, proxmoxID int, name string) *models.Guest {
	t.Helper()
	g := &models.Guest{
		Type:       models.GuestTypeCT,
		Name:       name,
		Status:     models.StatusRunning,
		ProxmoxID:  proxmoxID,
		InstanceID: instanceID,
	}
	if err := repo.UpsertGuest(t.Context(), g); err != nil {
		t.Fatalf("seed guest %q: %v", name, err)
	}
	guests, err := repo.ListGuests(t.Context())
	if err != nil {
		t.Fatalf("list guests: %v", err)
	}
	for _, got := range guests {
		if got.Name == name {
			return got
		}
	}
	t.Fatalf("seeded guest %q not found", name)
	return nil
}

// secretTokenValue is distinctive so a leak is unambiguous in an assertion.
const secretTokenValue = "SUPER-SECRET-PROXMOX-TOKEN"

// secretKeyValue stands in for an instance SSH private key.
const secretKeyValue = "-----BEGIN PRIVATE KEY-----\nSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n"

func listGuests(t *testing.T, h http.Handler, token string) []api.Guest {
	t.Helper()
	rec := getWithToken(t, h, "/session/guests", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("list guests: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var out []api.Guest
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// A client sees only the guests it has been granted.
func TestGuestListIsScopedToTheCaller(t *testing.T) {
	h, repo := newTestServer(t)
	inst := seedInstance(t, repo, "pve")
	mine := seedGuest(t, repo, inst.ID, 100, "mine")
	_ = seedGuest(t, repo, inst.ID, 999, "secret")

	client := seedClient(t, repo, userAliceName, "ssh-ed25519 AAAAalice alice")
	if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{mine.ID}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	cred := exchange(t, h, repo, &models.SessionIdentity{
		User: userAliasName, DisplayName: userAliceName, ClientID: client.ID,
	})

	got := listGuests(t, h, cred.Token)
	if len(got) != 1 {
		t.Fatalf("got %d guests, want 1: %+v", len(got), got)
	}
	if got[0].Name != "mine" {
		t.Errorf("got guest %q, want the granted one", got[0].Name)
	}
}

// The administrator sees everything.
func TestAdminSeesEveryGuest(t *testing.T) {
	h, repo := newTestServer(t)
	inst := seedInstance(t, repo, "pve")
	seedGuest(t, repo, inst.ID, 100, "one")
	seedGuest(t, repo, inst.ID, 101, "two")

	cred := exchange(t, h, repo, &models.SessionIdentity{
		User: userAliasName, DisplayName: api.AdminUser, IsAdmin: true,
	})

	if got := listGuests(t, h, cred.Token); len(got) != 2 {
		t.Fatalf("admin got %d guests, want 2", len(got))
	}
}

// The guest list is held for a whole session and mostly never connected to,
// so it must not carry anything that could reach a guest.
func TestGuestListCarriesNoCredentials(t *testing.T) {
	h, repo := newTestServer(t)
	inst := seedInstance(t, repo, "pve")
	seedGuest(t, repo, inst.ID, 100, "one")

	cred := exchange(t, h, repo, &models.SessionIdentity{
		User: userAliasName, DisplayName: api.AdminUser, IsAdmin: true,
	})

	rec := getWithToken(t, h, "/session/guests", cred.Token)
	if body := rec.Body.String(); strings.Contains(body, secretTokenValue) {
		t.Fatalf("the guest list leaked the API token secret: %s", body)
	}
}

// Connecting to a granted guest yields the credentials for its instance.
func TestConnectReturnsCredentialsForAGrantedGuest(t *testing.T) {
	h, repo := newTestServer(t)
	inst := seedInstance(t, repo, "pve")
	guest := seedGuest(t, repo, inst.ID, 100, "mine")

	client := seedClient(t, repo, userAliceName, "ssh-ed25519 AAAAalice alice")
	if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{guest.ID}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	cred := exchange(t, h, repo, &models.SessionIdentity{
		User: userAliasName, DisplayName: userAliceName, ClientID: client.ID,
	})

	rec := postWithToken(t, h,
		fmt.Sprintf("/session/connect/%d", guest.ID), cred.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var info api.ConnectInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.Guest.Name != "mine" {
		t.Errorf("guest = %q, want mine", info.Guest.Name)
	}
	if info.Instance.APITokenSecret == nil || *info.Instance.APITokenSecret != secretTokenValue {
		t.Errorf("the API token secret was not delivered: %+v", info.Instance)
	}
}

// THE central property of this PR: naming a guest you may not reach gets you
// nothing, and in particular no credentials.
func TestConnectRefusesAGuestTheCallerMayNotReach(t *testing.T) {
	h, repo := newTestServer(t)
	inst := seedInstance(t, repo, "pve")
	mine := seedGuest(t, repo, inst.ID, 100, "mine")
	secret := seedGuest(t, repo, inst.ID, 999, "secret")

	client := seedClient(t, repo, userAliceName, "ssh-ed25519 AAAAalice alice")
	if err := repo.GrantClientAccess(t.Context(), client.ID, []int64{mine.ID}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	cred := exchange(t, h, repo, &models.SessionIdentity{
		User: userAliasName, DisplayName: userAliceName, ClientID: client.ID,
	})

	rec := postWithToken(t, h,
		fmt.Sprintf("/session/connect/%d", secret.ID), cred.Token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: a client reached a guest it was "+
			"not granted: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, secretTokenValue) {
		t.Fatalf("a refused connect leaked the API token secret: %s", body)
	}
}

// A guest that does not exist must look exactly like one the caller may not
// reach, or ids become an enumeration oracle.
func TestConnectHidesWhetherAGuestExists(t *testing.T) {
	h, repo := newTestServer(t)
	inst := seedInstance(t, repo, "pve")
	secret := seedGuest(t, repo, inst.ID, 999, "secret")

	client := seedClient(t, repo, userAliceName, "ssh-ed25519 AAAAalice alice")
	cred := exchange(t, h, repo, &models.SessionIdentity{
		User: userAliasName, DisplayName: userAliceName, ClientID: client.ID,
	})

	forbidden := postWithToken(t, h,
		fmt.Sprintf("/session/connect/%d", secret.ID), cred.Token)
	missing := postWithToken(t, h, "/session/connect/999999", cred.Token)

	if forbidden.Code != missing.Code {
		t.Fatalf("an existing-but-forbidden guest answered %d while a "+
			"missing one answered %d: the difference reveals the cluster",
			forbidden.Code, missing.Code)
	}
	if forbidden.Body.String() != missing.Body.String() {
		t.Fatalf("bodies differ: %q vs %q",
			forbidden.Body.String(), missing.Body.String())
	}
}

// An instance whose key is a PATH must come back with the key inline: the
// session cannot read that file, which is the point.
func TestConnectResolvesAKeyPathIntoThePEM(t *testing.T) {
	h, repo := newTestServer(t)

	keyPath := t.TempDir() + "/id_ed25519"
	if err := os.WriteFile(keyPath, []byte(secretKeyValue), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	inst := &models.ProxmoxInstance{
		Name:           "pve",
		APIURL:         "https://pve:8006",
		ConnectionType: models.ConnectionTypeSSH,
		Node:           "pve1",
		SSHHost:        "pve",
		SSHPort:        22,
		SSHUser:        "root",
		SSHKeyPath:     keyPath,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	guest := seedGuest(t, repo, inst.ID, 100, "mine")

	cred := exchange(t, h, repo, &models.SessionIdentity{
		User: userAliasName, DisplayName: api.AdminUser, IsAdmin: true,
	})
	rec := postWithToken(t, h,
		fmt.Sprintf("/session/connect/%d", guest.ID), cred.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var info api.ConnectInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.Instance.SSHKey == nil || *info.Instance.SSHKey != secretKeyValue {
		t.Fatalf("the key path was not resolved into the PEM: %+v", info.Instance)
	}
}

// Connecting returns only the instance hosting that guest.
func TestConnectReturnsOnlyTheHostingInstance(t *testing.T) {
	h, repo := newTestServer(t)
	mineInst := seedInstance(t, repo, "mine")
	otherInst := &models.ProxmoxInstance{
		Name:           "other",
		APIURL:         "https://other:8006",
		APITokenSecret: "OTHER-INSTANCE-SECRET",
		ConnectionType: models.ConnectionTypeTermProxy,
		Node:           "pve2",
	}
	if err := repo.AddProxmoxInstance(t.Context(), otherInst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	seedGuest(t, repo, otherInst.ID, 200, "elsewhere")
	guest := seedGuest(t, repo, mineInst.ID, 100, "mine")

	cred := exchange(t, h, repo, &models.SessionIdentity{
		User: userAliasName, DisplayName: api.AdminUser, IsAdmin: true,
	})
	rec := postWithToken(t, h,
		fmt.Sprintf("/session/connect/%d", guest.ID), cred.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "OTHER-INSTANCE-SECRET") {
		t.Fatalf("connecting to one guest returned another instance's "+
			"secret: %s", body)
	}
}

func TestReservedLoginNames(t *testing.T) {
	h, repo := newTestServer(t)
	seedClient(t, repo, userAliceName, "ssh-ed25519 AAAAalice alice")
	cred := exchange(t, h, repo, &models.SessionIdentity{
		User: userAliasName, DisplayName: userAliceName, ClientID: 1,
	})

	for name, want := range map[string]bool{
		api.AdminUser: true,
		userAliceName: true,
		"ALICE":       true, // case-insensitive
		"ct100":       false,
		userAliasName: false,
	} {
		rec := getWithToken(t, h,
			"/session/login-name-reserved?name="+name, cred.Token)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", name, rec.Code)
		}
		var got struct {
			Reserved bool `json:"reserved"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if got.Reserved != want {
			t.Errorf("%q reserved = %v, want %v", name, got.Reserved, want)
		}
	}
}

func TestPublicEndpoint(t *testing.T) {
	h, repo := newTestServer(t)
	if err := repo.SetSetting(t.Context(), db.SettingPublicEndpoint, "proxpass.example.com"); err != nil {
		t.Fatalf("set: %v", err)
	}
	cred := exchange(t, h, repo, &models.SessionIdentity{
		User: userAliasName, DisplayName: api.AdminUser, IsAdmin: true,
	})

	rec := getWithToken(t, h, "/session/public-endpoint", cred.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Endpoint != "proxpass.example.com" {
		t.Errorf("endpoint = %q", got.Endpoint)
	}
}

// Every one of these must refuse an unauthenticated caller: they all return
// something about the cluster.
func TestSessionDataEndpointsNeedACredential(t *testing.T) {
	h, _ := newTestServer(t)

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/session/guests"},
		{http.MethodPost, "/session/connect/1"},
		{http.MethodGet, "/session/login-name-reserved?name=alice"},
		{http.MethodGet, "/session/public-endpoint"},
	} {
		var rec = getWithToken(t, h, tc.path, "")
		if tc.method == http.MethodPost {
			rec = postWithToken(t, h, tc.path, "")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a credential: status = %d, want 401",
				tc.method, tc.path, rec.Code)
		}
	}
}
