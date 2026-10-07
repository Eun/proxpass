package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	ucli "github.com/urfave/cli/v3"

	"proxpass/internal/db"
	"proxpass/internal/models"
)

// Fixture values for the instance under test.
const (
	testInstName = "pve1"
	testSSHAdmin = "admin"
)

// seedInstance stores one fully populated instance to update.
func seedInstance(t *testing.T) (db.Repository, *models.ProxmoxInstance) {
	t.Helper()
	repo, err := db.NewRepository(t.TempDir() + "/p.db")
	if err != nil {
		t.Fatalf("opening the repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	inst := &models.ProxmoxInstance{
		Name:             testInstName,
		APIURL:           "https://pve1:8006",
		APITokenID:       "root@pam!tok",
		APITokenSecret:   "SECRET",
		ConsoleTransport: models.ConsoleTransportTermProxy,
		Node:             testInstName,
		SSHHost:          testInstName,
		SSHPort:          22,
		SSHUser:          "root",
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	return repo, inst
}

// updateFlags runs applyInstanceFlags with argv, which is where the
// partial-update decisions live. The network-touching parts of the command
// are deliberately not exercised here.
func updateFlags(t *testing.T, inst *models.ProxmoxInstance, argv ...string) error {
	t.Helper()
	var applyErr error
	cmd := &ucli.Command{
		Flags:  instanceUpdateCmd(&Deps{}).Flags,
		Action: func(_ context.Context, c *ucli.Command) error { applyErr = applyInstanceFlags(c, inst); return nil },
	}
	full := append([]string{"update", "--name", inst.Name}, argv...)
	if err := cmd.Run(t.Context(), full); err != nil {
		return err
	}
	return applyErr
}

// TestUpdateChangesOnlyWhatWasNamed is the property the command turns on.
//
// Every other field has to survive untouched. The failure this guards against
// is silent: an update that also blanked the API token would leave an
// instance that lists guests fine until its credentials are next needed.
func TestUpdateChangesOnlyWhatWasNamed(t *testing.T) {
	_, inst := seedInstance(t)
	before := *inst

	if err := updateFlags(t, inst, "--ssh-user", testSSHAdmin); err != nil {
		t.Fatalf("update: %v", err)
	}

	if inst.SSHUser != testSSHAdmin {
		t.Errorf("ssh user = %q, want admin", inst.SSHUser)
	}
	// Everything else, field by field, because a struct copy would not say
	// WHICH field was clobbered.
	if inst.Name != before.Name {
		t.Errorf("name changed to %q", inst.Name)
	}
	if inst.APIURL != before.APIURL {
		t.Errorf("api url changed to %q", inst.APIURL)
	}
	if inst.APITokenID != before.APITokenID {
		t.Errorf("token id changed to %q", inst.APITokenID)
	}
	if inst.APITokenSecret != before.APITokenSecret {
		t.Errorf("token secret changed to %q", inst.APITokenSecret)
	}
	if inst.ConsoleTransport != before.ConsoleTransport {
		t.Errorf("console transport changed to %q", inst.ConsoleTransport)
	}
	if inst.SSHHost != before.SSHHost || inst.SSHPort != before.SSHPort {
		t.Errorf("ssh target changed to %s:%d", inst.SSHHost, inst.SSHPort)
	}
	if inst.Node != before.Node {
		t.Errorf("node changed to %q", inst.Node)
	}
}

// TestUpdateSSHHostAcceptsAPort covers the case that motivated this command:
// an SSH daemon that moved.
func TestUpdateSSHHostAcceptsAPort(t *testing.T) {
	_, inst := seedInstance(t)
	if err := updateFlags(t, inst, "--ssh-host", "pve1.internal:2222"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if inst.SSHHost != "pve1.internal" || inst.SSHPort != 2222 {
		t.Fatalf("ssh target = %s:%d, want pve1.internal:2222", inst.SSHHost, inst.SSHPort)
	}
}

// TestUpdateURLRederivesTheSSHHost checks that the two do not drift apart.
//
// The SSH host was derived from the URL when the instance was added, so
// moving the URL without moving it would leave the instance pointing its API
// at one machine and its file transfers at another.
func TestUpdateURLRederivesTheSSHHost(t *testing.T) {
	_, inst := seedInstance(t)
	if err := updateFlags(t, inst, "--url", "https://pve9.example.com:8006"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if inst.SSHHost != "pve9.example.com" {
		t.Fatalf("ssh host = %q, want pve9.example.com", inst.SSHHost)
	}
}

// TestUpdateURLKeepsAnExplicitSSHHost is the other half: when both are given,
// the explicit one wins rather than being overwritten by the derivation.
func TestUpdateURLKeepsAnExplicitSSHHost(t *testing.T) {
	_, inst := seedInstance(t)
	if err := updateFlags(t, inst,
		"--url", "https://pve9.example.com:8006",
		"--ssh-host", "mgmt.pve9:2222"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if inst.SSHHost != "mgmt.pve9" || inst.SSHPort != 2222 {
		t.Fatalf("ssh target = %s:%d, want mgmt.pve9:2222", inst.SSHHost, inst.SSHPort)
	}
}

// TestUpdateRejectsAnInvalidTransport keeps a typo from storing a value
// nothing can dispatch on.
func TestUpdateRejectsAnInvalidTransport(t *testing.T) {
	_, inst := seedInstance(t)
	err := updateFlags(t, inst, "--console-transport", "telnet")
	if err == nil {
		t.Fatal("expected an invalid transport to be refused")
	}
	if !strings.Contains(err.Error(), "termproxy") {
		t.Fatalf("the error should name the valid values: %v", err)
	}
}

// TestUpdateRejectsEmptyRequiredValues covers the fields where clearing is
// never what somebody meant: an unnamed instance cannot be addressed, and an
// empty SSH user would silently become root's business.
func TestUpdateRejectsEmptyRequiredValues(t *testing.T) {
	for _, flag := range []string{"--rename", "--ssh-user"} {
		_, inst := seedInstance(t)
		if err := updateFlags(t, inst, flag, ""); err == nil {
			t.Errorf("%s: expected an empty value to be refused", flag)
		}
	}
}

// TestUpdatePersistsThroughTheRepository checks the write actually lands,
// which the flag-level tests above do not reach.
func TestUpdatePersistsThroughTheRepository(t *testing.T) {
	repo, inst := seedInstance(t)

	inst.SSHUser = testSSHAdmin
	inst.SSHPort = 2222
	if err := repo.UpdateProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("update: %v", err)
	}

	stored, err := repo.ListProxmoxInstances(t.Context())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected one instance, got %d", len(stored))
	}
	if stored[0].SSHUser != testSSHAdmin || stored[0].SSHPort != 2222 {
		t.Fatalf("the update did not persist: %+v", stored[0])
	}
	// And the id is unchanged, because the access rules are keyed on it --
	// an update that replaced the row would silently drop them.
	if stored[0].ID != inst.ID {
		t.Fatalf("the instance id changed from %d to %d", inst.ID, stored[0].ID)
	}
}

// TestUpdateReportsAnUnknownInstance covers the ordinary typo.
func TestUpdateReportsAnUnknownInstance(t *testing.T) {
	repo, _ := seedInstance(t)
	var out bytes.Buffer
	deps := &Deps{Repo: repo, Out: &out, ErrOut: &out}

	_, err := findInstanceByName(t.Context(), deps, "nope")
	if err == nil {
		t.Fatal("expected an unknown instance to be reported")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Fatalf("the error should name the instance: %v", err)
	}
}
