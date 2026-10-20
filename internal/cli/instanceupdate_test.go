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
	full := append([]string{"update", flagArgName, inst.Name}, argv...)
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

// TestUpdateURLLeavesTheSSHHostUntouched pins the decision that --url never
// touches the SSH host. The host is never derived from the API URL -- the API
// address is just as often a bare IP or an alias that does not resolve from
// where proxpass runs -- so moving the URL must leave the stored SSH host
// exactly as it was. (--url still re-resolves the node name; that is a
// separate, network-touching step not exercised here.)
func TestUpdateURLLeavesTheSSHHostUntouched(t *testing.T) {
	_, inst := seedInstance(t)
	before := inst.SSHHost
	beforePort := inst.SSHPort
	if err := updateFlags(t, inst, "--url", "https://pve9.example.com:8006"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if inst.SSHHost != before || inst.SSHPort != beforePort {
		t.Fatalf("ssh target = %s:%d, want it unchanged at %s:%d",
			inst.SSHHost, inst.SSHPort, before, beforePort)
	}
}

// TestUpdateChangesTheSSHHostIndependentlyOfURL is the other half: --url and
// --ssh-host are independent, so an explicit --ssh-host sets the host whether
// or not --url is also given.
func TestUpdateChangesTheSSHHostIndependentlyOfURL(t *testing.T) {
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

// TestUpdateWarnsWhenTheInstanceHasNoSSHHost drives the real `instance update'
// command and checks that an instance left without an SSH host is called out:
// its console may work, but node shell, SFTP and file transfer cannot, and the
// administrator is told how to fix it. Updating only --ssh-user touches no
// network, so this exercises the wiring without a mock Proxmox API.
func TestUpdateWarnsWhenTheInstanceHasNoSSHHost(t *testing.T) {
	repo, err := db.NewRepository(t.TempDir() + "/p.db")
	if err != nil {
		t.Fatalf("opening the repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	// An instance with no SSH host, as `instance add' now stores one when
	// --ssh-host is omitted.
	inst := &models.ProxmoxInstance{
		Name:             testInstName,
		APIURL:           "https://pve1:8006",
		APITokenID:       "root@pam!tok",
		APITokenSecret:   "SECRET",
		ConsoleTransport: models.ConsoleTransportTermProxy,
		Node:             testInstName,
		SSHUser:          testSSHUser,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	out, err := runCLI(t, repo, cmdInstance, "update", flagArgName, testInstName, "--ssh-user", "admin")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !strings.Contains(out, "no SSH host") || !strings.Contains(out, "SFTP") {
		t.Fatalf("expected a missing-ssh-host warning:\n%s", out)
	}
	if !strings.Contains(out, "--ssh-host") {
		t.Fatalf("expected the warning to say how to set a host:\n%s", out)
	}
}
