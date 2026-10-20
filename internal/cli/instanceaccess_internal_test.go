package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"proxpass/internal/db"
	"proxpass/internal/models"

	ucli "github.com/urfave/cli/v3"
)

// `access grant|ls|revoke --instance' grants a shell on the Proxmox node
// itself rather than a console on a guest.
//
// Driven through the real command rather than the helpers, because the flag
// wiring is half the change: --guest stopped being Required when --instance
// arrived, and nothing but running the command proves the pair is still
// mutually exhaustive.

const (
	testNode   = "rome"
	testClient = "alice"
	// argv[0], as the real binary is invoked.
	testBinary = "proxpass"
)

// runAccess invokes an `access' subcommand and returns what it printed.
func runAccess(t *testing.T, repo db.Repository, args ...string) (string, error) {
	t.Helper()
	return runCLI(t, repo, args...)
}

// runCLI invokes any subcommand through the real command tree and returns
// what it printed.
//
// The whole tree rather than one command, so a test exercises the same
// wiring the binary does -- flag definitions included, which is where the
// behavior under test often lives.
func runCLI(t *testing.T, repo db.Repository, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	// A key service so the instance commands can report the public key without
	// reading the root-owned file (which the CLI no longer does). A canned
	// public key and "reachable" answer keep these end-to-end tests off the
	// network; the real file read and dial are tested in internal/api.
	deps := &Deps{
		Repo:    repo,
		Out:     &out,
		ErrOut:  &out,
		SSHKeys: &fakeSSHKeys{pub: testPubKey, path: testKeyPath},
	}
	cmd := &ucli.Command{Commands: []*ucli.Command{
		accessCmd(deps),
		clientCmd(deps),
		groupCmd(deps),
		instanceCmd(deps),
	}}
	err := cmd.Run(context.Background(), append([]string{testBinary}, args...))
	return out.String(), err
}

// newInstanceAccessRepo seeds one node and one client on it.
func newInstanceAccessRepo(t *testing.T) (db.Repository, *models.ProxmoxInstance) {
	t.Helper()
	repo, err := db.NewSQLiteRepository(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	inst := &models.ProxmoxInstance{
		Name: testNode, APIURL: testRomeURL, Node: testNode,
		ConsoleTransport: models.ConsoleTransportTermProxy,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	if err := repo.AddClient(t.Context(), &models.Client{
		Name: testClient, PublicKeys: []string{"ssh-ed25519 AAAA test"},
		GroupIDs: []int64{},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}
	return repo, inst
}

func TestGrantAndRevokeAnInstance(t *testing.T) {
	repo, inst := newInstanceAccessRepo(t)

	out, err := runAccess(t, repo,
		"access", "grant", "--client", testClient, "--instance", testNode)
	if err != nil {
		t.Fatalf("grant: %v (output %q)", err, out)
	}
	// Named as a node, so the line cannot be mistaken for a guest grant.
	if !strings.Contains(out, "node "+testNode) {
		t.Errorf("grant did not report a node grant: %q", out)
	}

	client, _ := repo.GetClientByName(t.Context(), testClient)
	ok, err := repo.HasInstanceAccess(t.Context(), client.ID, inst.ID)
	if err != nil {
		t.Fatalf("HasInstanceAccess: %v", err)
	}
	if !ok {
		t.Fatal("the grant did not reach the database")
	}

	if out, err = runAccess(t, repo,
		"access", "revoke", "--client", testClient, "--instance", testNode); err != nil {
		t.Fatalf("revoke: %v (output %q)", err, out)
	}
	ok, _ = repo.HasInstanceAccess(t.Context(), client.ID, inst.ID)
	if ok {
		t.Error("the instance is still reachable after revoke")
	}
}

// An unknown node is refused rather than silently granting nothing.
func TestGrantingAnUnknownInstanceFails(t *testing.T) {
	repo, _ := newInstanceAccessRepo(t)

	_, err := runAccess(t, repo,
		"access", "grant", "--client", testClient, "--instance", "nowhere")
	if err == nil {
		t.Fatal("granting an unknown instance succeeded")
	}
	if !strings.Contains(err.Error(), "nowhere") {
		t.Errorf("the error does not name the instance: %v", err)
	}
}

// Instance names match case-insensitively, as they do in a login name.
//
// `instance add' stores whatever case was typed, and `<name>@proxpass'
// resolves case-insensitively, so an exact-match grant would fail for a node
// a client can reach perfectly well.
func TestGrantingAnInstanceIsCaseInsensitive(t *testing.T) {
	repo, inst := newInstanceAccessRepo(t)

	if out, err := runAccess(t, repo,
		"access", "grant", "--client", testClient, "--instance", "ROME"); err != nil {
		t.Fatalf("grant: %v (output %q)", err, out)
	}
	client, _ := repo.GetClientByName(t.Context(), testClient)
	ok, _ := repo.HasInstanceAccess(t.Context(), client.ID, inst.ID)
	if !ok {
		t.Error("a differently-cased instance name did not resolve")
	}
}

// --guest was Required before --instance existed. One of the two is now
// required instead, which no flag definition can express.
func TestGrantNeedsAtLeastOneTarget(t *testing.T) {
	repo, _ := newInstanceAccessRepo(t)

	_, err := runAccess(t, repo, "access", "grant", "--client", testClient)
	if err == nil {
		t.Fatal("a grant with no target succeeded")
	}
	if !strings.Contains(err.Error(), "--guest") ||
		!strings.Contains(err.Error(), "--instance") {
		t.Errorf("the error does not name both target flags: %v", err)
	}
}

// Granting a guest and a node in one command is two rules, not an error.
func TestGrantAcceptsBothTargetsAtOnce(t *testing.T) {
	repo, inst := newInstanceAccessRepo(t)
	if err := repo.UpsertGuest(t.Context(), &models.Guest{
		Type: models.GuestTypeCT, Name: "web", Status: models.StatusRunning,
		ProxmoxID: 100, InstanceID: inst.ID,
	}); err != nil {
		t.Fatalf("upsert guest: %v", err)
	}

	out, err := runAccess(t, repo, "access", "grant",
		"--client", testClient, "--guest", "ct100", "--instance", testNode)
	if err != nil {
		t.Fatalf("grant: %v (output %q)", err, out)
	}

	client, _ := repo.GetClientByName(t.Context(), testClient)
	guests, _ := repo.ListGuests(t.Context())
	if ok, _ := repo.HasAccess(t.Context(), client.ID, guests[0].ID); !ok {
		t.Error("the guest half of the grant did not land")
	}
	if ok, _ := repo.HasInstanceAccess(t.Context(), client.ID, inst.ID); !ok {
		t.Error("the instance half of the grant did not land")
	}
}

// `access ls' must show both kinds, and say which is which.
func TestAccessLsShowsNodeRules(t *testing.T) {
	repo, inst := newInstanceAccessRepo(t)
	// A guest sharing the node's name, so KIND is the only thing telling
	// the two rows apart.
	if err := repo.UpsertGuest(t.Context(), &models.Guest{
		Type: models.GuestTypeCT, Name: testNode, Status: models.StatusRunning,
		ProxmoxID: 100, InstanceID: inst.ID,
	}); err != nil {
		t.Fatalf("upsert guest: %v", err)
	}
	if out, err := runAccess(t, repo, "access", "grant",
		"--client", testClient, "--guest", "ct100", "--instance", testNode); err != nil {
		t.Fatalf("grant: %v (output %q)", err, out)
	}

	out, err := runAccess(t, repo, "access", "ls")
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	if !strings.Contains(out, "KIND") {
		t.Errorf("ls has no KIND column: %q", out)
	}
	if !strings.Contains(out, "node") {
		t.Errorf("ls does not show the node rule: %q", out)
	}
	if !strings.Contains(out, "guest") {
		t.Errorf("ls does not show the guest rule: %q", out)
	}
}

// The JSON form keeps guest rules under their own key, so a consumer that
// predates node rules keeps working.
func TestAccessLsJSONSeparatesTheTwoKinds(t *testing.T) {
	repo, _ := newInstanceAccessRepo(t)
	if out, err := runAccess(t, repo,
		"access", "grant", "--client", testClient, "--instance", testNode); err != nil {
		t.Fatalf("grant: %v (output %q)", err, out)
	}

	out, err := runAccess(t, repo, "access", "ls", "--format", "json")
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	if !strings.Contains(out, `"guests"`) || !strings.Contains(out, `"instances"`) {
		t.Errorf("json output does not carry both keys: %q", out)
	}
	if !strings.Contains(out, `"instance_id"`) {
		t.Errorf("json output does not carry the instance target: %q", out)
	}
}
