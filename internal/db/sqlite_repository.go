package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	_ "modernc.org/sqlite"
	"proxpass/internal/models"
)

type sqliteRepo struct {
	db *sql.DB
}

func NewSQLiteRepository(dbPath string) (*sqliteRepo, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	schema := []string{
		`CREATE TABLE IF NOT EXISTS proxmox_instances (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hostname TEXT NOT NULL,
			port INTEGER NOT NULL,
			api_key TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS guests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			name TEXT NOT NULL,
			status TEXT NOT NULL,
			proxmox_id INTEGER NOT NULL,
			instance_id INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS clients (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			public_keys TEXT NOT NULL,
			group_ids TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			client_ids TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS access_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			subject_id INTEGER NOT NULL,
			guest_id INTEGER NOT NULL,
			UNIQUE(type, subject_id, guest_id)
		)`,
		`CREATE TABLE IF NOT EXISTS default_policy (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			authorized_client_ids TEXT NOT NULL,
			authorized_group_ids TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS admin_keys (
			public_key TEXT PRIMARY KEY
		)`,
	}

	for _, s := range schema {
		if _, err := db.Exec(s); err != nil {
			return nil, fmt.Errorf("failed to execute schema: %w", err)
		}
	}

	return &sqliteRepo{db: db}, nil
}

func (r *sqliteRepo) Close() error {
	return r.db.Close()
}

// --- Proxmox Instances ---

func (r *sqliteRepo) AddProxmoxInstance(ctx context.Context, inst *models.ProxmoxInstance) error {
	res, err := r.db.ExecContext(ctx,
		"INSERT INTO proxmox_instances (hostname, port, api_key) VALUES (?, ?, ?)",
		inst.Hostname, inst.Port, inst.APIKey)
	if err != nil {
		return err
	}
	inst.ID, err = res.LastInsertId()
	return err
}

func (r *sqliteRepo) ListProxmoxInstances(ctx context.Context) ([]*models.ProxmoxInstance, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, hostname, port, api_key FROM proxmox_instances")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var list []*models.ProxmoxInstance
	for rows.Next() {
		inst := &models.ProxmoxInstance{}
		if err := rows.Scan(&inst.ID, &inst.Hostname, &inst.Port, &inst.APIKey); err != nil {
			return nil, err
		}
		list = append(list, inst)
	}
	return list, rows.Err()
}

func (r *sqliteRepo) UpdateProxmoxInstance(ctx context.Context, inst *models.ProxmoxInstance) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE proxmox_instances SET hostname = ?, port = ?, api_key = ? WHERE id = ?",
		inst.Hostname, inst.Port, inst.APIKey, inst.ID)
	return err
}

func (r *sqliteRepo) RemoveProxmoxInstance(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM proxmox_instances WHERE id = ?", id)
	return err
}

// --- Guests ---

func (r *sqliteRepo) UpsertGuest(ctx context.Context, guest *models.Guest) error {
	err := r.db.QueryRowContext(ctx,
		"SELECT id FROM guests WHERE proxmox_id = ? AND instance_id = ?",
		guest.ProxmoxID, guest.InstanceID).Scan(&guest.ID)
	if err == sql.ErrNoRows {
		res, err := r.db.ExecContext(ctx,
			"INSERT INTO guests (type, name, status, proxmox_id, instance_id) VALUES (?, ?, ?, ?, ?)",
			guest.Type, guest.Name, guest.Status, guest.ProxmoxID, guest.InstanceID)
		if err != nil {
			return err
		}
		guest.ID, err = res.LastInsertId()
		return err
	} else if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"UPDATE guests SET type=?, name=?, status=? WHERE id=?",
		guest.Type, guest.Name, guest.Status, guest.ID)
	return err
}

func (r *sqliteRepo) ListGuests(ctx context.Context) ([]*models.Guest, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, type, name, status, proxmox_id, instance_id FROM guests")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var list []*models.Guest
	for rows.Next() {
		g := &models.Guest{}
		if err := rows.Scan(&g.ID, &g.Type, &g.Name, &g.Status, &g.ProxmoxID, &g.InstanceID); err != nil {
			return nil, err
		}
		list = append(list, g)
	}
	return list, rows.Err()
}

func (r *sqliteRepo) GetGuestByID(ctx context.Context, id int64) (*models.Guest, error) {
	g := &models.Guest{}
	err := r.db.QueryRowContext(ctx,
		"SELECT id, type, name, status, proxmox_id, instance_id FROM guests WHERE id = ?", id).
		Scan(&g.ID, &g.Type, &g.Name, &g.Status, &g.ProxmoxID, &g.InstanceID)
	if err != nil {
		return nil, err
	}
	return g, nil
}

// --- Clients ---

func (r *sqliteRepo) AddClient(ctx context.Context, client *models.Client) error {
	keysJSON, _ := json.Marshal(client.PublicKeys)
	groupsJSON, _ := json.Marshal(client.GroupIDs)
	res, err := r.db.ExecContext(ctx,
		"INSERT INTO clients (name, public_keys, group_ids) VALUES (?, ?, ?)",
		client.Name, string(keysJSON), string(groupsJSON))
	if err != nil {
		return err
	}
	client.ID, err = res.LastInsertId()
	return err
}

func (r *sqliteRepo) ListClients(ctx context.Context) ([]*models.Client, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, name, public_keys, group_ids FROM clients")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var list []*models.Client
	for rows.Next() {
		c := &models.Client{}
		var keysStr, groupsStr string
		if err := rows.Scan(&c.ID, &c.Name, &keysStr, &groupsStr); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(keysStr), &c.PublicKeys)
		_ = json.Unmarshal([]byte(groupsStr), &c.GroupIDs)
		list = append(list, c)
	}
	return list, rows.Err()
}

func (r *sqliteRepo) UpdateClient(ctx context.Context, client *models.Client) error {
	keysJSON, _ := json.Marshal(client.PublicKeys)
	groupsJSON, _ := json.Marshal(client.GroupIDs)
	_, err := r.db.ExecContext(ctx,
		"UPDATE clients SET name = ?, public_keys = ?, group_ids = ? WHERE id = ?",
		client.Name, string(keysJSON), string(groupsJSON), client.ID)
	return err
}

func (r *sqliteRepo) RemoveClient(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM clients WHERE id = ?", id)
	return err
}

func (r *sqliteRepo) GetClientByName(ctx context.Context, name string) (*models.Client, error) {
	c := &models.Client{}
	var keysStr, groupsStr string
	err := r.db.QueryRowContext(ctx,
		"SELECT id, name, public_keys, group_ids FROM clients WHERE name = ?", name).
		Scan(&c.ID, &c.Name, &keysStr, &groupsStr)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(keysStr), &c.PublicKeys)
	_ = json.Unmarshal([]byte(groupsStr), &c.GroupIDs)
	return c, nil
}

// --- Groups ---

func (r *sqliteRepo) AddGroup(ctx context.Context, group *models.Group) error {
	clientIDsJSON, _ := json.Marshal(group.ClientIDs)
	res, err := r.db.ExecContext(ctx,
		"INSERT INTO groups (name, client_ids) VALUES (?, ?)",
		group.Name, string(clientIDsJSON))
	if err != nil {
		return err
	}
	group.ID, err = res.LastInsertId()
	return err
}

func (r *sqliteRepo) ListGroups(ctx context.Context) ([]*models.Group, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, name, client_ids FROM groups")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var list []*models.Group
	for rows.Next() {
		g := &models.Group{}
		var clientIDsStr string
		if err := rows.Scan(&g.ID, &g.Name, &clientIDsStr); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(clientIDsStr), &g.ClientIDs)
		list = append(list, g)
	}
	return list, rows.Err()
}

func (r *sqliteRepo) UpdateGroup(ctx context.Context, group *models.Group) error {
	clientIDsJSON, _ := json.Marshal(group.ClientIDs)
	_, err := r.db.ExecContext(ctx,
		"UPDATE groups SET name = ?, client_ids = ? WHERE id = ?",
		group.Name, string(clientIDsJSON), group.ID)
	return err
}

func (r *sqliteRepo) RemoveGroup(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM groups WHERE id = ?", id)
	return err
}

// --- Access Rules ---

func (r *sqliteRepo) ListAccessRules(ctx context.Context) ([]*models.AccessRuleRow, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, type, subject_id, guest_id FROM access_rules ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var list []*models.AccessRuleRow
	for rows.Next() {
		ar := &models.AccessRuleRow{}
		var ruleType string
		if err := rows.Scan(&ar.ID, &ruleType, &ar.SubjectID, &ar.GuestID); err != nil {
			return nil, err
		}
		ar.Type = models.RuleType(ruleType)
		list = append(list, ar)
	}
	return list, rows.Err()
}

func (r *sqliteRepo) GrantClientAccess(ctx context.Context, clientID int64, guestIDs []int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx,
		"INSERT OR IGNORE INTO access_rules (type, subject_id, guest_id) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, gid := range guestIDs {
		if _, err := stmt.ExecContext(ctx, models.RuleClient, clientID, gid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *sqliteRepo) GrantGroupAccess(ctx context.Context, groupID int64, guestIDs []int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx,
		"INSERT OR IGNORE INTO access_rules (type, subject_id, guest_id) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, gid := range guestIDs {
		if _, err := stmt.ExecContext(ctx, models.RuleGroup, groupID, gid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *sqliteRepo) RevokeClientAccess(ctx context.Context, clientID int64, guestID int64) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM access_rules WHERE type = ? AND subject_id = ? AND guest_id = ?",
		models.RuleClient, clientID, guestID)
	return err
}

func (r *sqliteRepo) RevokeGroupAccess(ctx context.Context, groupID int64, guestID int64) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM access_rules WHERE type = ? AND subject_id = ? AND guest_id = ?",
		models.RuleGroup, groupID, guestID)
	return err
}

// --- Default Policy ---

func (r *sqliteRepo) SetDefaultPolicy(ctx context.Context, policy *models.DefaultAccessPolicy) error {
	clientIDsJSON, _ := json.Marshal(policy.AuthorizedClientIDs)
	groupIDsJSON, _ := json.Marshal(policy.AuthorizedGroupIDs)
	_, err := r.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO default_policy (id, authorized_client_ids, authorized_group_ids) VALUES (1, ?, ?)",
		string(clientIDsJSON), string(groupIDsJSON))
	return err
}

func (r *sqliteRepo) GetDefaultPolicy(ctx context.Context) (*models.DefaultAccessPolicy, error) {
	policy := &models.DefaultAccessPolicy{}
	var clientIDsStr, groupIDsStr string
	err := r.db.QueryRowContext(ctx,
		"SELECT authorized_client_ids, authorized_group_ids FROM default_policy WHERE id = 1").
		Scan(&clientIDsStr, &groupIDsStr)
	if err == sql.ErrNoRows {
		return policy, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(clientIDsStr), &policy.AuthorizedClientIDs)
	_ = json.Unmarshal([]byte(groupIDsStr), &policy.AuthorizedGroupIDs)
	return policy, nil
}

// --- Admin Keys ---

func (r *sqliteRepo) AddAdminKey(ctx context.Context, pubKey string) error {
	_, err := r.db.ExecContext(ctx, "INSERT OR IGNORE INTO admin_keys (public_key) VALUES (?)", pubKey)
	return err
}

func (r *sqliteRepo) ListAdminKeys(ctx context.Context) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT public_key FROM admin_keys")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var list []string
	for rows.Next() {
		var pk string
		if err := rows.Scan(&pk); err != nil {
			return nil, err
		}
		list = append(list, pk)
	}
	return list, rows.Err()
}

func (r *sqliteRepo) RemoveAdminKey(ctx context.Context, pubKey string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM admin_keys WHERE public_key = ?", pubKey)
	return err
}

// --- Access Control Check ---

// HasAccess returns true if clientID is allowed to reach guestID.
// Priority: explicit client rule > group rule > default policy.
func (r *sqliteRepo) HasAccess(ctx context.Context, clientID int64, guestID int64) (bool, error) {
	// 1. Direct client rule
	var exists int
	err := r.db.QueryRowContext(ctx,
		"SELECT 1 FROM access_rules WHERE type = ? AND subject_id = ? AND guest_id = ? LIMIT 1",
		models.RuleClient, clientID, guestID).Scan(&exists)
	if err == nil {
		return true, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}

	// 2. Group rules — load the client's group memberships
	var groupsJSON string
	err = r.db.QueryRowContext(ctx,
		"SELECT group_ids FROM clients WHERE id = ?", clientID).Scan(&groupsJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	var groupIDs []int64
	_ = json.Unmarshal([]byte(groupsJSON), &groupIDs)

	for _, gid := range groupIDs {
		err = r.db.QueryRowContext(ctx,
			"SELECT 1 FROM access_rules WHERE type = ? AND subject_id = ? AND guest_id = ? LIMIT 1",
			models.RuleGroup, gid, guestID).Scan(&exists)
		if err == nil {
			return true, nil
		}
		if err != sql.ErrNoRows {
			return false, err
		}
	}

	// 3. Default policy — client or any of its groups listed as authorized
	policy, err := r.GetDefaultPolicy(ctx)
	if err != nil {
		return false, err
	}
	for _, cid := range policy.AuthorizedClientIDs {
		if cid == clientID {
			return true, nil
		}
	}
	for _, authGID := range policy.AuthorizedGroupIDs {
		for _, memberGID := range groupIDs {
			if authGID == memberGID {
				return true, nil
			}
		}
	}

	return false, nil
}
