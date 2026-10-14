package cli

import (
	"strings"
	"testing"

	"proxpass/internal/db"
	"proxpass/internal/models"
)

// Names the CLI accepts are matched case-insensitively.
//
// They were not, consistently: `access grant --instance ROME' resolved while
// `instance rm ROME' did not, because one used EqualFold and the other ==.
// An administrator should not have to remember how they capitalized a name
// when they created it.
//
// Three lookups are covered here and three deliberately are NOT:
//
//   - api/server.go handleUserByName, which picks between the admin gid and
//     the alias gid. Relaxing it would hand "ADMIN" a gid that can write the
//     database -- the opposite of what the comment there asks for.
//   - api/server.go handleGroupByName, which serves a gid to NSS.
//   - the group lookups in policy.go and access.go, which write a subject_id
//     into an access rule. Group names are not validated, so "ops" and "Ops"
//     can both exist; a case-insensitive scan would then attach the grant to
//     whichever came first, silently.
//
// Those need the UNIQUE constraints to be case-insensitive first, which is a
// migration that fails on any database already holding both spellings.

// newNameRepo seeds one of each kind of named thing.
func newNameRepo(t *testing.T) db.Repository {
	t.Helper()
	repo, err := db.NewSQLiteRepository(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	if err := repo.AddProxmoxInstance(t.Context(), &models.ProxmoxInstance{
		Name: testNode, APIURL: testRomeURL, Node: testNode,
		ConsoleTransport: models.ConsoleTransportTermProxy,
		SSHHost:          testNode, SSHPort: 22, SSHUser: testSSHUser,
	}); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	if err := repo.AddClient(t.Context(), &models.Client{
		Name: "alice", PublicKeys: []string{"ssh-ed25519 AAAA test"},
		GroupIDs: []int64{},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}
	if err := repo.AddGroup(t.Context(), &models.Group{
		Name: "ops", ClientIDs: []int64{},
	}); err != nil {
		t.Fatalf("add group: %v", err)
	}
	return repo
}

func TestRemoveCommandsMatchNamesCaseInsensitively(t *testing.T) {
	for _, tc := range []struct {
		what  string
		args  []string
		gone  func(t *testing.T, repo db.Repository) bool
		typed string
	}{
		{
			what:  "client",
			args:  []string{"client", "rm", flagArgName, "ALICE"},
			typed: "ALICE",
			gone: func(t *testing.T, repo db.Repository) bool {
				t.Helper()
				clients, _ := repo.ListClients(t.Context())
				return len(clients) == 0
			},
		},
		{
			what:  "group",
			args:  []string{"group", "rm", flagArgName, "OPS"},
			typed: "OPS",
			gone: func(t *testing.T, repo db.Repository) bool {
				t.Helper()
				groups, _ := repo.ListGroups(t.Context())
				return len(groups) == 0
			},
		},
		{
			what:  "instance",
			args:  []string{cmdInstance, "rm", flagArgName, "RoMe"},
			typed: "RoMe",
			gone: func(t *testing.T, repo db.Repository) bool {
				t.Helper()
				instances, _ := repo.ListProxmoxInstances(t.Context())
				return len(instances) == 0
			},
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			repo := newNameRepo(t)
			out, err := runCLI(t, repo, tc.args...)
			if err != nil {
				t.Fatalf("%s rm %s: %v (output %q)", tc.what, tc.typed, err, out)
			}
			if !tc.gone(t, repo) {
				t.Errorf("%s rm %s did not remove anything", tc.what, tc.typed)
			}
		})
	}
}

// `instance update' resolves the same way, so a rename can be driven with
// whatever case is to hand.
func TestInstanceUpdateMatchesNameCaseInsensitively(t *testing.T) {
	repo := newNameRepo(t)

	out, err := runCLI(t, repo,
		cmdInstance, "update", flagArgName, "ROME", "--rename", "roma")
	if err != nil {
		t.Fatalf("update: %v (output %q)", err, out)
	}

	instances, _ := repo.ListProxmoxInstances(t.Context())
	if len(instances) != 1 || instances[0].Name != "roma" {
		t.Errorf("instance was not renamed: %+v", instances)
	}
}

// A name that matches nothing is still an error, whatever its case: the
// relaxation must not turn a typo into a silent success.
func TestAnUnknownNameIsStillRefused(t *testing.T) {
	repo := newNameRepo(t)

	_, err := runCLI(t, repo, cmdInstance, "rm", flagArgName, "NOWHERE")
	if err == nil {
		t.Fatal("removing an unknown instance succeeded")
	}
	if !strings.Contains(err.Error(), "NOWHERE") {
		t.Errorf("the error does not name what was asked for: %v", err)
	}
}
