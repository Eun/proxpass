package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"proxpass/internal/api"
	"proxpass/internal/db"
	"proxpass/internal/models"
)

// The node endpoints are the instance counterpart of the guest ones, and
// these mirror the guest tests deliberately: the properties that matter are
// the same ones, and a reader comparing the two files should see the same
// shape.

// seedNode adds an instance that a node connection can actually use.
//
// seedInstance deliberately leaves ssh_host empty -- a guest console over
// termproxy needs none -- but a NODE is reached only over SSH, so these
// tests need an instance that was configured for it.
func seedNode(t *testing.T, repo db.Repository, name string) *models.ProxmoxInstance {
	t.Helper()
	inst := seedInstance(t, repo, name)
	inst.SSHHost = name + ".example.com"
	inst.SSHPort = 22
	inst.SSHUser = testSSHUser
	if err := repo.UpdateProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("configure ssh on %q: %v", name, err)
	}
	return inst
}

// grantedName is the instance/guest a test grants; ungrantedName is the one
// it must not reach.
const (
	grantedName   = "mine"
	ungrantedName = "secret"
	testGroupName = "ops"
)

func listInstances(t *testing.T, h http.Handler, token string) []api.Instance {
	t.Helper()
	rec := getWithToken(t, h, "/session/instances", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("list instances: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var out []api.Instance
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// testClient seeds the client these tests act as.
func testClient(t *testing.T, repo db.Repository) *models.Client {
	t.Helper()
	return seedClient(t, repo, userAliceName, "ssh-ed25519 AAAAalice alice")
}

// A client sees only the instances it has been granted.
func TestInstanceListIsScopedToTheCaller(t *testing.T) {
	h, repo := newTestServer(t)
	mine := seedNode(t, repo, grantedName)
	seedNode(t, repo, ungrantedName)

	client := testClient(t, repo)
	if err := repo.GrantClientInstanceAccess(t.Context(), client.ID, []int64{mine.ID}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: client.ID,
	})

	got := listInstances(t, h, cred.Token)
	if len(got) != 1 {
		t.Fatalf("got %d instances, want 1: %+v", len(got), got)
	}
	if got[0].Name != grantedName {
		t.Errorf("instance = %q, want %q", got[0].Name, grantedName)
	}
}

func TestAdminSeesEveryInstance(t *testing.T) {
	h, repo := newTestServer(t)
	seedNode(t, repo, "one")
	seedNode(t, repo, "two")

	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: api.AdminUser, IdentityName: api.AdminUser, IsAdmin: true,
	})

	if got := listInstances(t, h, cred.Token); len(got) != 2 {
		t.Fatalf("an administrator saw %d of 2 instances: %+v", len(got), got)
	}
}

// The list is held for a session's whole life, so it must carry nothing
// that could be used to reach a node.
func TestInstanceListCarriesNoCredentials(t *testing.T) {
	h, repo := newTestServer(t)
	inst := seedNode(t, repo, testInstanceName)

	client := testClient(t, repo)
	if err := repo.GrantClientInstanceAccess(t.Context(), client.ID, []int64{inst.ID}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: client.ID,
	})

	rec := getWithToken(t, h, "/session/instances", cred.Token)
	for _, secret := range []string{secretTokenValue, "root@pam!tok"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("the instance list leaked %q: %s", secret, rec.Body.String())
		}
	}
}

func TestConnectNodeReturnsCredentialsForAGrantedInstance(t *testing.T) {
	h, repo := newTestServer(t)
	inst := seedNode(t, repo, testInstanceName)

	client := testClient(t, repo)
	if err := repo.GrantClientInstanceAccess(t.Context(), client.ID, []int64{inst.ID}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: client.ID,
	})

	rec := postWithToken(t, h,
		fmt.Sprintf("/session/node/%d", inst.ID), cred.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got api.InstanceCredentials
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SSHHost == nil || *got.SSHHost != testInstanceName+".example.com" {
		t.Errorf("sshHost = %v, want the configured host", got.SSHHost)
	}
	if got.SSHUser == nil || *got.SSHUser != testSSHUser {
		t.Errorf("sshUser = %v, want %q", got.SSHUser, testSSHUser)
	}
	if got.Node != testNodeName {
		t.Errorf("node = %q, want %q", got.Node, testNodeName)
	}
}

// THE central property: a grant is required, and a refusal leaks nothing.
func TestConnectNodeRefusesAnInstanceTheCallerMayNotReach(t *testing.T) {
	h, repo := newTestServer(t)
	mine := seedNode(t, repo, grantedName)
	secret := seedNode(t, repo, ungrantedName)

	client := testClient(t, repo)
	if err := repo.GrantClientInstanceAccess(t.Context(), client.ID, []int64{mine.ID}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: client.ID,
	})

	rec := postWithToken(t, h,
		fmt.Sprintf("/session/node/%d", secret.ID), cred.Token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: a client reached a node it was "+
			"not granted: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, secretTokenValue) {
		t.Fatalf("a refused node connect leaked the API token secret: %s", body)
	}
}

// An instance that does not exist must look exactly like one the caller may
// not reach, or ids become an enumeration oracle.
func TestConnectNodeHidesWhetherAnInstanceExists(t *testing.T) {
	h, repo := newTestServer(t)
	secret := seedNode(t, repo, ungrantedName)

	client := testClient(t, repo)
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: client.ID,
	})

	forbidden := postWithToken(t, h,
		fmt.Sprintf("/session/node/%d", secret.ID), cred.Token)
	missing := postWithToken(t, h, "/session/node/999999", cred.Token)

	if forbidden.Code != missing.Code {
		t.Fatalf("an existing-but-forbidden instance answered %d while a "+
			"missing one answered %d: the difference reveals the cluster",
			forbidden.Code, missing.Code)
	}
	if forbidden.Body.String() != missing.Body.String() {
		t.Fatalf("bodies differ: %q vs %q",
			forbidden.Body.String(), missing.Body.String())
	}
}

// A grant on one kind of target must not reach the other.
//
// Both directions, in one table because the symmetry IS the property: a
// guest grant must not reach the node hosting it, and a node grant must not
// reach the guests it hosts. The first direction is the privilege
// escalation -- a shell on the node is strictly more than one guest on it --
// and the second is the one an implementation is most likely to get wrong
// by deriving one list from the other.
//
// Each case asserts the granted side is reachable first, so neither can
// pass vacuously by granting nothing.
//
// The two cases are mirror images BY DESIGN -- same shape, opposite
// direction -- and that symmetry is the property being asserted. Factoring
// the remaining difference out would leave a parameterised parameter table
// and hide which direction each case actually tests.
//
//nolint:dupl // mirror-image cases; the symmetry is the assertion
func TestAGrantDoesNotCrossBetweenGuestsAndNodes(t *testing.T) {
	for _, tc := range []struct {
		name string
		// grant gives the client the one target it is entitled to.
		grant func(t *testing.T, repo db.Repository, clientID int64, inst *models.ProxmoxInstance, guest *models.Guest)
		// wantGuests and wantInstances are what should be visible.
		wantGuests, wantInstances int
		// path is the connect endpoint that must still refuse.
		path func(inst *models.ProxmoxInstance, guest *models.Guest) string
		// what names the thing that must not be reached.
		what string
	}{
		{
			name: "a guest grant does not reach its node",
			grant: func(t *testing.T, repo db.Repository, clientID int64, _ *models.ProxmoxInstance, guest *models.Guest) {
				t.Helper()
				if err := repo.GrantClientAccess(t.Context(), clientID, []int64{guest.ID}); err != nil {
					t.Fatalf("grant guest: %v", err)
				}
			},
			wantGuests:    1,
			wantInstances: 0,
			path: func(inst *models.ProxmoxInstance, _ *models.Guest) string {
				return fmt.Sprintf("/session/node/%d", inst.ID)
			},
			what: "a shell on its node",
		},
		{
			name: "a node grant does not reach its guests",
			grant: func(t *testing.T, repo db.Repository, clientID int64, inst *models.ProxmoxInstance, _ *models.Guest) {
				t.Helper()
				if err := repo.GrantClientInstanceAccess(t.Context(), clientID, []int64{inst.ID}); err != nil {
					t.Fatalf("grant node: %v", err)
				}
			},
			wantGuests:    0,
			wantInstances: 1,
			path: func(_ *models.ProxmoxInstance, guest *models.Guest) string {
				return fmt.Sprintf("/session/connect/%d", guest.ID)
			},
			what: "a guest console",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, repo := newTestServer(t)
			inst := seedNode(t, repo, testInstanceName)
			guest := seedGuest(t, repo, inst.ID, 100, grantedName)

			client := testClient(t, repo)
			tc.grant(t, repo, client.ID, inst, guest)
			cred := exchange(t, h, repo, &models.SessionIdentity{
				LoginName: userAliasName, IdentityName: userAliceName, ClientID: client.ID,
			})

			if got := listGuests(t, h, cred.Token); len(got) != tc.wantGuests {
				t.Errorf("saw %d guests, want %d: %+v", len(got), tc.wantGuests, got)
			}
			if got := listInstances(t, h, cred.Token); len(got) != tc.wantInstances {
				t.Errorf("saw %d instances, want %d: %+v", len(got), tc.wantInstances, got)
			}

			rec := postWithToken(t, h, tc.path(inst, guest), cred.Token)
			if rec.Code != http.StatusForbidden {
				t.Errorf("the grant reached %s: status = %d, want 403: %s",
					tc.what, rec.Code, rec.Body.String())
			}
		})
	}
}

// The default policy reaches guests but must NOT reach nodes.
//
// Pinned at the HTTP layer as well as the repository, because this is the
// tier whose omission is a deliberate decision rather than an oversight:
// the policy names no target, so honoring it would hand every covered
// client a shell on every node.
func TestTheDefaultPolicyDoesNotListNodes(t *testing.T) {
	h, repo := newTestServer(t)
	inst := seedNode(t, repo, testInstanceName)
	seedGuest(t, repo, inst.ID, 100, "anything")

	client := testClient(t, repo)
	if err := repo.SetDefaultPolicy(t.Context(), &models.DefaultAccessPolicy{
		AuthorizedClientIDs: []int64{client.ID},
	}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: client.ID,
	})

	// The policy DOES reach the guest, so this test cannot pass vacuously.
	if got := listGuests(t, h, cred.Token); len(got) != 1 {
		t.Fatalf("precondition: the default policy did not reach the guest: %+v", got)
	}

	if got := listInstances(t, h, cred.Token); len(got) != 0 {
		t.Errorf("the default policy listed a node: %+v", got)
	}
	rec := postWithToken(t, h,
		fmt.Sprintf("/session/node/%d", inst.ID), cred.Token)
	if rec.Code != http.StatusForbidden {
		t.Errorf("the default policy reached a node shell: status = %d, want 403: %s",
			rec.Code, rec.Body.String())
	}
}

// A group grant reaches the node, like a client grant.
func TestAGroupGrantReachesTheNode(t *testing.T) {
	h, repo := newTestServer(t)
	inst := seedNode(t, repo, testInstanceName)

	client := testClient(t, repo)
	group := &models.Group{Name: testGroupName, ClientIDs: []int64{client.ID}}
	if err := repo.AddGroup(t.Context(), group); err != nil {
		t.Fatalf("add group: %v", err)
	}
	client.GroupIDs = []int64{group.ID}
	if err := repo.UpdateClient(t.Context(), client); err != nil {
		t.Fatalf("update client: %v", err)
	}
	if err := repo.GrantGroupInstanceAccess(t.Context(), group.ID, []int64{inst.ID}); err != nil {
		t.Fatalf("grant group: %v", err)
	}
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: client.ID,
	})

	if got := listInstances(t, h, cred.Token); len(got) != 1 {
		t.Fatalf("a group grant did not reach the node: %+v", got)
	}
}

// An instance with no ssh-host cannot be opened, and says so.
//
// Not a 403: the caller WAS granted this node, so refusing as if they were
// not would send them looking for a permission problem that is not there.
func TestConnectNodeReportsAnInstanceWithNoSSHHost(t *testing.T) {
	h, repo := newTestServer(t)
	// seedInstance, not seedNode: no ssh_host.
	inst := seedInstance(t, repo, testInstanceName)

	client := testClient(t, repo)
	if err := repo.GrantClientInstanceAccess(t.Context(), client.ID, []int64{inst.ID}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	cred := exchange(t, h, repo, &models.SessionIdentity{
		LoginName: userAliasName, IdentityName: userAliceName, ClientID: client.ID,
	})

	rec := postWithToken(t, h,
		fmt.Sprintf("/session/node/%d", inst.ID), cred.Token)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("a granted-but-unreachable node answered 403, which sends "+
			"the caller looking for a permission problem: %s", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
}

// Both new endpoints must refuse an unauthenticated caller.
func TestNodeEndpointsNeedACredential(t *testing.T) {
	h, _ := newTestServer(t)

	if rec := getWithToken(t, h, "/session/instances", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /session/instances without a credential: status = %d, want 401", rec.Code)
	}
	if rec := postWithToken(t, h, "/session/node/1", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /session/node/1 without a credential: status = %d, want 401", rec.Code)
	}
}
