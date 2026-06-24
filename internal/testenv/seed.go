package testenv

import (
	"context"
	"fmt"

	"proxpass/internal/db"
	"proxpass/internal/models"
)

// SeedData holds references to all seeded entities for use in tests.
type SeedData struct {
	Instance *models.ProxmoxInstance
	Guests   []*models.Guest
	Client   *models.Client
	Group    *models.Group
	AdminKey string
}

// Seed populates the repository with a standard test dataset.
// The instance fields (APIURL, SSHHost, etc.) are set to the
// provided values so they can point at mock servers.
func Seed(repo db.Repository, apiURL, sshHost string, sshPort int, sshKeyPath string) (*SeedData, error) {
	ctx := context.Background()

	// 1. Proxmox instance
	inst := &models.ProxmoxInstance{
		Name:           "test-pve",
		APIURL:         apiURL,
		APITokenID:     "testuser@pam!testtoken",
		APITokenSecret: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		SSHHost:        sshHost,
		SSHPort:        sshPort,
		SSHUser:        "root",
		SSHKeyPath:     sshKeyPath,
	}
	if err := repo.AddProxmoxInstance(ctx, inst); err != nil {
		return nil, fmt.Errorf("add instance: %w", err)
	}

	// Re-read to get the assigned ID
	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}
	inst = instances[0]

	// 2. Guests (simulating what discovery would insert)
	guests := []*models.Guest{
		{Type: models.GuestTypeCT, Name: "webserver", Status: models.StatusRunning, ProxmoxID: 100, InstanceID: inst.ID},
		{Type: models.GuestTypeCT, Name: "database", Status: models.StatusRunning, ProxmoxID: 101, InstanceID: inst.ID},
		{Type: models.GuestTypeVM, Name: "devbox", Status: models.StatusRunning, ProxmoxID: 200, InstanceID: inst.ID},
		{Type: models.GuestTypeVM, Name: "staging", Status: models.StatusStopped, ProxmoxID: 201, InstanceID: inst.ID},
	}
	for _, g := range guests {
		if err := repo.UpsertGuest(ctx, g); err != nil {
			return nil, fmt.Errorf("upsert guest %s: %w", g.Name, err)
		}
	}
	// Re-read to get assigned IDs
	guests2, err := repo.ListGuests(ctx)
	if err != nil {
		return nil, fmt.Errorf("list guests: %w", err)
	}

	// 3. Group
	grp := &models.Group{Name: "developers"}
	if err := repo.AddGroup(ctx, grp); err != nil {
		return nil, fmt.Errorf("add group: %w", err)
	}
	groups, err := repo.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	grp = groups[0]

	// 4. Client with a test public key, member of the group
	//    Using a deterministic key for testing purposes.
	testPubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKtQq3JoWT2wvR6g9GnbFZ4uhEghOK+vLHMosTGlLiYP test@proxpass"
	client := &models.Client{
		Name:       "alice",
		PublicKeys: []string{testPubKey},
		GroupIDs:   []int64{grp.ID},
	}
	if err := repo.AddClient(ctx, client); err != nil {
		return nil, fmt.Errorf("add client: %w", err)
	}
	clients, err := repo.ListClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	client = clients[0]

	// 5. Access rules — alice can access webserver directly
	if err := repo.GrantClientAccess(ctx, client.ID, []int64{guests2[0].ID}); err != nil {
		return nil, fmt.Errorf("grant client access: %w", err)
	}

	// 6. Group access — developers group can access devbox
	if err := repo.GrantGroupAccess(ctx, grp.ID, []int64{guests2[2].ID}); err != nil {
		return nil, fmt.Errorf("grant group access: %w", err)
	}

	// 7. Admin key
	adminKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMWAqn6LGXNU6drRd+7YW5MHTIpk0mmJ6XBrjKkOxpCX admin@proxpass"
	if err := repo.AddAdminKey(ctx, adminKey); err != nil {
		return nil, fmt.Errorf("add admin key: %w", err)
	}

	// 8. Default policy — empty (deny by default)
	if err := repo.SetDefaultPolicy(ctx, &models.DefaultAccessPolicy{}); err != nil {
		return nil, fmt.Errorf("set default policy: %w", err)
	}

	return &SeedData{
		Instance: inst,
		Guests:   guests2,
		Client:   client,
		Group:    grp,
		AdminKey: adminKey,
	}, nil
}
