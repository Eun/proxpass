package db

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // register the "pgx" driver
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // register the "sqlite" driver

	"proxpass/internal/models"
)

//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var migrationsFS embed.FS

// sqlRepo implements Repository against any database/sql backend.
//
// The queries are written once with "?" placeholders and rebound per dialect
// on the way out, so there is a single set of statements rather than one per
// backend that could drift apart.
type sqlRepo struct {
	db *sql.DB
	d  *dialect
}

// exec, query and queryRow rebind the statement before handing it to the
// driver. Every call site uses these rather than r.db directly; a stray
// r.db.ExecContext would work on SQLite and fail on Postgres, which is
// exactly the kind of bug that only shows up in the backend you test least.
func (r *sqlRepo) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return r.db.ExecContext(ctx, r.d.rebind(q), args...)
}

func (r *sqlRepo) query(ctx context.Context, q string) (*sql.Rows, error) {
	return r.db.QueryContext(ctx, r.d.rebind(q))
}

func (r *sqlRepo) queryRow(ctx context.Context, q string, args ...any) *sql.Row {
	return r.db.QueryRowContext(ctx, r.d.rebind(q), args...)
}

// busyTimeout is how long a writer waits for a competing lock before giving
// up. Several processes share the database: "proxpass serve" writes on every
// discovery pass while each "proxpass session" and "authorized-keys"
// invocation reads. Without a timeout SQLite fails such a collision
// immediately with SQLITE_BUSY, which surfaces as a failed login or a lost
// discovery pass.
const busyTimeout = 5 * time.Second

// NewSQLiteRepository opens the SQLite database at dbPath.
//
// Kept as the name callers and tests already use; it is now a thin wrapper
// over NewRepository.
func NewSQLiteRepository(dbPath string) (Repository, error) {
	// WAL lets readers proceed while a writer holds the lock, which is the
	// normal case here: discovery writes while sessions read.
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)",
		dbPath, busyTimeout.Milliseconds())
	return open(BackendSQLite, dsn)
}

// NewRepository opens whichever backend the DSN names.
//
// A Postgres URL ("postgres://..." or "postgresql://...") selects Postgres;
// anything else is a SQLite path. Inferring from the DSN rather than adding a
// separate backend flag means there is one setting to get right instead of
// two that can disagree -- a Postgres URL with the backend left at "sqlite"
// would otherwise create a confusing file named after the URL.
func NewRepository(dsn string) (Repository, error) {
	if isPostgresDSN(dsn) {
		return open(BackendPostgres, dsn)
	}
	return NewSQLiteRepository(dsn)
}

// isPostgresDSN reports whether dsn names a Postgres server.
func isPostgresDSN(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") ||
		strings.HasPrefix(dsn, "postgresql://")
}

// open connects, migrates and returns the repository.
func open(backend Backend, dsn string) (Repository, error) {
	d, err := dialectFor(backend)
	if err != nil {
		return nil, err
	}
	database, err := sql.Open(d.driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	if err := migrate(database, &d); err != nil {
		_ = database.Close()
		return nil, err
	}
	return &sqlRepo{db: database, d: &d}, nil
}

// migrate brings the schema up to date.
//
// goose keeps its dialect and base filesystem in package-level state, so the
// two settings are applied together here rather than once at init: a process
// that opened both backends would otherwise run one's migrations against the
// other.
func migrate(database *sql.DB, d *dialect) error {
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect(d.goose); err != nil {
		return fmt.Errorf("goose set dialect: %w", err)
	}
	goose.SetLogger(goose.NopLogger())
	if err := goose.Up(database, d.migrations); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	// After goose, which is what creates the tables this reads: names stored
	// before they were folded have to be brought into the form lookups now
	// assume, and a database holding two names that differ only by case has
	// to be refused rather than silently half-folded. See foldStoredNames.
	return foldStoredNames(context.Background(), database, d)
}

func (r *sqlRepo) Close() error {
	return r.db.Close()
}

// encodeFingerprints / decodeFingerprints store a Proxmox instance's pinned SSH
// host-key fingerprints in the single ssh_fingerprint TEXT column as a
// newline-separated list. A fingerprint is a "SHA256:<base64>" token that never
// contains a newline, so the join is unambiguous, and this needs no schema
// change: an existing row holding one bare fingerprint decodes to a one-element
// list, and an empty column decodes to no pins (SSHFP fallback) -- so old rows
// keep verifying without a migration.
func encodeFingerprints(fps []string) string {
	out := make([]string, 0, len(fps))
	for _, fp := range fps {
		if fp = strings.TrimSpace(fp); fp != "" {
			out = append(out, fp)
		}
	}
	return strings.Join(out, "\n")
}

func decodeFingerprints(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// boolToInt maps a Go bool to the 0/1 INTEGER used for boolean columns. The
// schema stores booleans as INTEGER (not BOOLEAN) so one scan path serves both
// SQLite and Postgres; see the session-token and 00010 migrations.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// --- Proxmox Instances ---

func (r *sqlRepo) AddProxmoxInstance(ctx context.Context, inst *models.ProxmoxInstance) error {
	// Normalise the URL before storing so the UNIQUE constraint compares
	// canonical forms (no trailing slashes).
	inst.APIURL = strings.TrimRight(inst.APIURL, "/")
	// And the name, for the same reason: folded here, UNIQUE(name) is a
	// case-insensitive constraint. See models.FoldName.
	//
	// Assigned back into the caller's struct rather than only into the bind
	// argument, so that what the caller goes on to print and compare is what
	// was actually stored. `instance add' re-finds the row it just created by
	// matching inst.Name against the listed rows, to get the id discovery
	// needs; were the struct left holding the typed spelling that match would
	// fail and discovery would silently never run.
	inst.Name = models.FoldName(inst.Name)
	err := r.queryRow(ctx,
		`INSERT INTO proxmox_instances
		(name, api_url, api_token_id, api_token_secret, console_transport, node,
		 insecure_tls, insecure_ssh, ssh_host, ssh_port, ssh_user, ssh_fingerprint)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		RETURNING id`,
		inst.Name, inst.APIURL, inst.APITokenID, inst.APITokenSecret,
		string(inst.ConsoleTransport), inst.Node,
		boolToInt(inst.InsecureTLS), boolToInt(inst.InsecureSSH),
		inst.SSHHost, inst.SSHPort, inst.SSHUser,
		encodeFingerprints(inst.SSHFingerprints),
	).Scan(&inst.ID)
	if err != nil {
		if r.d.isUniqueViolation(err) {
			if strings.Contains(err.Error(), "api_url") {
				return fmt.Errorf("an instance with api-url %q already exists", inst.APIURL)
			}
			return fmt.Errorf("an instance named %q already exists", inst.Name)
		}
		return err
	}
	return nil
}

func (r *sqlRepo) ListProxmoxInstances(ctx context.Context) ([]*models.ProxmoxInstance, error) {
	rows, err := r.query(ctx,
		// Ordered by id so the listing is stable. Without ORDER BY the order
		// is whatever SQLite happens to return, which is usually insertion
		// order but is not promised and changes after a row is deleted and
		// its rowid reused.
		`SELECT id, name, api_url, api_token_id, api_token_secret,
		console_transport, node,
		insecure_tls, insecure_ssh, ssh_host, ssh_port, ssh_user, ssh_fingerprint
		FROM proxmox_instances ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var list []*models.ProxmoxInstance
	for rows.Next() {
		inst := &models.ProxmoxInstance{}
		var connType string
		// The insecure flags are stored as INTEGER (not BOOLEAN) so one scan
		// path serves both SQLite and Postgres; see the 00010 migration.
		var insecureTLS, insecureSSH int64
		var fpStr string
		if err := rows.Scan(
			&inst.ID, &inst.Name, &inst.APIURL,
			&inst.APITokenID, &inst.APITokenSecret,
			&connType, &inst.Node,
			&insecureTLS, &insecureSSH, &inst.SSHHost, &inst.SSHPort, &inst.SSHUser,
			&fpStr,
		); err != nil {
			return nil, err
		}
		inst.ConsoleTransport = models.ConsoleTransport(connType)
		inst.InsecureTLS = insecureTLS != 0
		inst.InsecureSSH = insecureSSH != 0
		inst.SSHFingerprints = decodeFingerprints(fpStr)
		list = append(list, inst)
	}
	return list, rows.Err()
}

func (r *sqlRepo) UpdateProxmoxInstance(ctx context.Context, inst *models.ProxmoxInstance) error {
	inst.APIURL = strings.TrimRight(inst.APIURL, "/")
	inst.Name = models.FoldName(inst.Name)
	_, err := r.exec(ctx,
		`UPDATE proxmox_instances SET
		name = ?, api_url = ?, api_token_id = ?,
		api_token_secret = ?, console_transport = ?, node = ?,
		insecure_tls = ?, insecure_ssh = ?, ssh_host = ?, ssh_port = ?,
		ssh_user = ?, ssh_fingerprint = ?
		WHERE id = ?`,
		inst.Name, inst.APIURL, inst.APITokenID,
		inst.APITokenSecret, string(inst.ConsoleTransport), inst.Node,
		boolToInt(inst.InsecureTLS), boolToInt(inst.InsecureSSH),
		inst.SSHHost, inst.SSHPort,
		inst.SSHUser, encodeFingerprints(inst.SSHFingerprints), inst.ID,
	)
	if err != nil && r.d.isUniqueViolation(err) {
		if strings.Contains(err.Error(), "api_url") {
			return fmt.Errorf("an instance with api-url %q already exists", inst.APIURL)
		}
		return fmt.Errorf("an instance named %q already exists", inst.Name)
	}
	return err
}

func (r *sqlRepo) RemoveProxmoxInstance(ctx context.Context, id int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Collect guest IDs belonging to this instance so we can remove their
	// access rules before deleting the guests themselves.
	rows, err := tx.QueryContext(ctx, r.d.rebind("SELECT id FROM guests WHERE instance_id = ?"), id)
	if err != nil {
		return err
	}
	var guestIDs []int64
	for rows.Next() {
		var gid int64
		if err := rows.Scan(&gid); err != nil {
			_ = rows.Close()
			return err
		}
		guestIDs = append(guestIDs, gid)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// Delete access rules that reference any of these guests.
	for _, gid := range guestIDs {
		if _, err := tx.ExecContext(ctx, r.d.rebind("DELETE FROM access_rules WHERE guest_id = ?"), gid); err != nil {
			return err
		}
	}

	// Delete the guests themselves.
	if _, err := tx.ExecContext(ctx, r.d.rebind("DELETE FROM guests WHERE instance_id = ?"), id); err != nil {
		return err
	}

	// And any rule granting access to the instance ITSELF, for the same
	// reason the guest rules go above: proxmox_instances.id is
	// AUTOINCREMENT and instance_access_rules has no foreign key, so a rule
	// left behind would start granting a node shell to whoever later
	// occupied this row id.
	if _, err := tx.ExecContext(ctx,
		r.d.rebind("DELETE FROM instance_access_rules WHERE instance_id = ?"), id); err != nil {
		return err
	}

	// Finally remove the instance.
	if _, err := tx.ExecContext(ctx, r.d.rebind("DELETE FROM proxmox_instances WHERE id = ?"), id); err != nil {
		return err
	}

	return tx.Commit()
}

// --- Guests ---

func (r *sqlRepo) UpsertGuest(ctx context.Context, guest *models.Guest) error {
	err := r.queryRow(ctx,
		"SELECT id FROM guests WHERE proxmox_id = ? AND instance_id = ?",
		guest.ProxmoxID, guest.InstanceID).Scan(&guest.ID)
	if err == sql.ErrNoRows {
		return r.queryRow(ctx,
			`INSERT INTO guests (type, name, status, proxmox_id, instance_id)
			 VALUES (?, ?, ?, ?, ?) RETURNING id`,
			guest.Type, guest.Name, guest.Status, guest.ProxmoxID, guest.InstanceID,
		).Scan(&guest.ID)
	} else if err != nil {
		return err
	}
	_, err = r.exec(ctx,
		"UPDATE guests SET type=?, name=?, status=? WHERE id=?",
		guest.Type, guest.Name, guest.Status, guest.ID)
	return err
}

func (r *sqlRepo) ListGuests(ctx context.Context) ([]*models.Guest, error) {
	rows, err := r.query(ctx, "SELECT id, type, name, status, proxmox_id, instance_id FROM guests")
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

func (r *sqlRepo) GetGuestByID(ctx context.Context, id int64) (*models.Guest, error) {
	g := &models.Guest{}
	err := r.queryRow(ctx,
		"SELECT id, type, name, status, proxmox_id, instance_id FROM guests WHERE id = ?", id).
		Scan(&g.ID, &g.Type, &g.Name, &g.Status, &g.ProxmoxID, &g.InstanceID)
	if err != nil {
		return nil, err
	}
	return g, nil
}

// RemoveGuestsNotIn deletes guests of an instance that the last discovery
// pass did not report, together with any access rules pointing at them.
//
// Discovery is otherwise append-only, so a guest that is stopped or destroyed
// on the Proxmox host would linger in the list forever: it would still be
// offered by the picker and still resolve by name, then fail at connect time
// because pct enter and qm terminal only work on a running guest.
//
// Deleting the access rules alongside the guests matters because guests.id is
// AUTOINCREMENT but access_rules.guest_id has no foreign key: a stale rule
// would keep granting access to whatever guest later occupied that row id.
func (r *sqlRepo) RemoveGuestsNotIn(ctx context.Context, instanceID int64, keep []int) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Collect the row ids to drop. Doing this in Go rather than with a
	// NOT IN (...) clause keeps the statement free of dynamic SQL.
	rows, err := tx.QueryContext(ctx, r.d.rebind("SELECT id, proxmox_id FROM guests WHERE instance_id = ?"), instanceID)
	if err != nil {
		return 0, fmt.Errorf("select guests: %w", err)
	}
	keepSet := make(map[int]struct{}, len(keep))
	for _, vmid := range keep {
		keepSet[vmid] = struct{}{}
	}
	var stale []int64
	for rows.Next() {
		var id int64
		var vmid int
		if err := rows.Scan(&id, &vmid); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan guest: %w", err)
		}
		if _, ok := keepSet[vmid]; !ok {
			stale = append(stale, id)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("iterate guests: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close rows: %w", err)
	}
	if len(stale) == 0 {
		return 0, nil
	}

	for _, id := range stale {
		if _, err := tx.ExecContext(ctx, r.d.rebind("DELETE FROM access_rules WHERE guest_id = ?"), id); err != nil {
			return 0, fmt.Errorf("delete access rules for guest %d: %w", id, err)
		}
		if _, err := tx.ExecContext(ctx, r.d.rebind("DELETE FROM guests WHERE id = ?"), id); err != nil {
			return 0, fmt.Errorf("delete guest %d: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return len(stale), nil
}

// --- Clients ---

func (r *sqlRepo) AddClient(ctx context.Context, client *models.Client) error {
	client.Name = models.FoldName(client.Name)
	keysJSON, _ := json.Marshal(client.PublicKeys)
	groupsJSON, _ := json.Marshal(client.GroupIDs)
	return r.queryRow(ctx,
		`INSERT INTO clients (name, public_keys, group_ids)
		 VALUES (?, ?, ?) RETURNING id`,
		client.Name, string(keysJSON), string(groupsJSON),
	).Scan(&client.ID)
}

func (r *sqlRepo) ListClients(ctx context.Context) ([]*models.Client, error) {
	rows, err := r.query(ctx, "SELECT id, name, public_keys, group_ids FROM clients")
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

func (r *sqlRepo) UpdateClient(ctx context.Context, client *models.Client) error {
	client.Name = models.FoldName(client.Name)
	keysJSON, _ := json.Marshal(client.PublicKeys)
	groupsJSON, _ := json.Marshal(client.GroupIDs)
	_, err := r.exec(ctx,
		"UPDATE clients SET name = ?, public_keys = ?, group_ids = ? WHERE id = ?",
		client.Name, string(keysJSON), string(groupsJSON), client.ID)
	return err
}

func (r *sqlRepo) RemoveClient(ctx context.Context, id int64) error {
	_, err := r.exec(ctx, "DELETE FROM clients WHERE id = ?", id)
	return err
}

func (r *sqlRepo) GetClientByName(ctx context.Context, name string) (*models.Client, error) {
	c := &models.Client{}
	var keysStr, groupsStr string
	err := r.queryRow(ctx,
		// Plain equality against a folded argument. Names are folded on the
		// way in (see models.FoldName), so every stored name is already in
		// this form and an exact match finds a client by whatever case the
		// caller typed -- while still using the UNIQUE(name) index rather
		// than scanning, which `WHERE lower(name) = lower(?)' would not.
		//
		// UNIQUE(name) over folded values is also what makes the answer
		// single: two rows differing only by case cannot both exist, so this
		// cannot return a row chosen by scan order.
		"SELECT id, name, public_keys, group_ids FROM clients WHERE name = ?",
		models.FoldName(name)).
		Scan(&c.ID, &c.Name, &keysStr, &groupsStr)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(keysStr), &c.PublicKeys)
	_ = json.Unmarshal([]byte(groupsStr), &c.GroupIDs)
	return c, nil
}

// --- Groups ---

func (r *sqlRepo) AddGroup(ctx context.Context, group *models.Group) error {
	group.Name = models.FoldName(group.Name)
	clientIDsJSON, _ := json.Marshal(group.ClientIDs)
	return r.queryRow(ctx,
		`INSERT INTO groups (name, client_ids)
		 VALUES (?, ?) RETURNING id`,
		group.Name, string(clientIDsJSON),
	).Scan(&group.ID)
}

func (r *sqlRepo) ListGroups(ctx context.Context) ([]*models.Group, error) {
	rows, err := r.query(ctx, "SELECT id, name, client_ids FROM groups")
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

func (r *sqlRepo) UpdateGroup(ctx context.Context, group *models.Group) error {
	group.Name = models.FoldName(group.Name)
	clientIDsJSON, _ := json.Marshal(group.ClientIDs)
	_, err := r.exec(ctx,
		"UPDATE groups SET name = ?, client_ids = ? WHERE id = ?",
		group.Name, string(clientIDsJSON), group.ID)
	return err
}

func (r *sqlRepo) RemoveGroup(ctx context.Context, id int64) error {
	_, err := r.exec(ctx, "DELETE FROM groups WHERE id = ?", id)
	return err
}

// --- Access Rules ---

func (r *sqlRepo) ListAccessRules(ctx context.Context) ([]*models.AccessRuleRow, error) {
	rows, err := r.query(ctx, "SELECT id, type, subject_id, guest_id FROM access_rules ORDER BY id")
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

// grantAccess is the shared helper for GrantClientAccess and GrantGroupAccess.
func (r *sqlRepo) grantAccess(ctx context.Context, ruleType models.RuleType, subjectID int64, guestIDs []int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, r.d.rebind(
		`INSERT INTO access_rules (type, subject_id, guest_id) VALUES (?, ?, ?)
		 ON CONFLICT (type, subject_id, guest_id) DO NOTHING`))
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, gid := range guestIDs {
		if _, err := stmt.ExecContext(ctx, ruleType, subjectID, gid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *sqlRepo) GrantClientAccess(ctx context.Context, clientID int64, guestIDs []int64) error {
	return r.grantAccess(ctx, models.RuleClient, clientID, guestIDs)
}

func (r *sqlRepo) GrantGroupAccess(ctx context.Context, groupID int64, guestIDs []int64) error {
	return r.grantAccess(ctx, models.RuleGroup, groupID, guestIDs)
}

func (r *sqlRepo) RevokeClientAccess(ctx context.Context, clientID, guestID int64) error {
	_, err := r.exec(ctx,
		"DELETE FROM access_rules WHERE type = ? AND subject_id = ? AND guest_id = ?",
		models.RuleClient, clientID, guestID)
	return err
}

func (r *sqlRepo) RevokeGroupAccess(ctx context.Context, groupID, guestID int64) error {
	_, err := r.exec(ctx,
		"DELETE FROM access_rules WHERE type = ? AND subject_id = ? AND guest_id = ?",
		models.RuleGroup, groupID, guestID)
	return err
}

// --- Instance Access Rules ---

// Instance rules are stored and queried exactly like guest rules, against a
// different table and target column. The statements are built from those two
// names rather than written out twice, so the two families cannot drift --
// which matters here, because the thing they have in common is an access
// decision.
const (
	instanceRuleTable = "instance_access_rules"
	instanceRuleCol   = "instance_id"
)

func (r *sqlRepo) ListInstanceAccessRules(ctx context.Context) ([]*models.InstanceAccessRuleRow, error) {
	rows, err := r.query(ctx, "SELECT id, type, subject_id, "+instanceRuleCol+
		" FROM "+instanceRuleTable+" ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var list []*models.InstanceAccessRuleRow
	for rows.Next() {
		ar := &models.InstanceAccessRuleRow{}
		var ruleType string
		if err := rows.Scan(&ar.ID, &ruleType, &ar.SubjectID, &ar.InstanceID); err != nil {
			return nil, err
		}
		ar.Type = models.RuleType(ruleType)
		list = append(list, ar)
	}
	return list, rows.Err()
}

// grantInstanceAccess is the shared helper for the two instance grants.
func (r *sqlRepo) grantInstanceAccess(
	ctx context.Context, ruleType models.RuleType, subjectID int64, instanceIDs []int64,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, r.d.rebind(
		"INSERT INTO "+instanceRuleTable+" (type, subject_id, "+instanceRuleCol+
			") VALUES (?, ?, ?) ON CONFLICT (type, subject_id, "+instanceRuleCol+
			") DO NOTHING"))
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, iid := range instanceIDs {
		if _, err := stmt.ExecContext(ctx, ruleType, subjectID, iid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *sqlRepo) GrantClientInstanceAccess(ctx context.Context, clientID int64, instanceIDs []int64) error {
	return r.grantInstanceAccess(ctx, models.RuleClient, clientID, instanceIDs)
}

func (r *sqlRepo) GrantGroupInstanceAccess(ctx context.Context, groupID int64, instanceIDs []int64) error {
	return r.grantInstanceAccess(ctx, models.RuleGroup, groupID, instanceIDs)
}

// revokeInstanceAccess deletes one rule, whatever its subject kind.
func (r *sqlRepo) revokeInstanceAccess(
	ctx context.Context, ruleType models.RuleType, subjectID, instanceID int64,
) error {
	_, err := r.exec(ctx, "DELETE FROM "+instanceRuleTable+
		" WHERE type = ? AND subject_id = ? AND "+instanceRuleCol+" = ?",
		ruleType, subjectID, instanceID)
	return err
}

func (r *sqlRepo) RevokeClientInstanceAccess(ctx context.Context, clientID, instanceID int64) error {
	return r.revokeInstanceAccess(ctx, models.RuleClient, clientID, instanceID)
}

func (r *sqlRepo) RevokeGroupInstanceAccess(ctx context.Context, groupID, instanceID int64) error {
	return r.revokeInstanceAccess(ctx, models.RuleGroup, groupID, instanceID)
}

// --- Default Policy ---

func (r *sqlRepo) SetDefaultPolicy(ctx context.Context, policy *models.DefaultAccessPolicy) error {
	clientIDsJSON, _ := json.Marshal(policy.AuthorizedClientIDs)
	groupIDsJSON, _ := json.Marshal(policy.AuthorizedGroupIDs)
	_, err := r.exec(ctx,
		`INSERT INTO default_policy (id, authorized_client_ids, authorized_group_ids)
		 VALUES (1, ?, ?)
		 ON CONFLICT (id) DO UPDATE SET
		   authorized_client_ids = excluded.authorized_client_ids,
		   authorized_group_ids  = excluded.authorized_group_ids`,
		string(clientIDsJSON), string(groupIDsJSON))
	return err
}

func (r *sqlRepo) GetDefaultPolicy(ctx context.Context) (*models.DefaultAccessPolicy, error) {
	policy := &models.DefaultAccessPolicy{}
	var clientIDsStr, groupIDsStr string
	err := r.queryRow(ctx,
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

// --- Settings ---

// SetSetting stores a configuration value, replacing any previous one.
func (r *sqlRepo) SetSetting(ctx context.Context, key, value string) error {
	_, err := r.exec(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// GetSetting returns a configuration value, or "" when it has never been set.
//
// An unset value is not an error: every caller wants the same fallback, and a
// fresh database legitimately has none of these.
func (r *sqlRepo) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := r.queryRow(ctx,
		"SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

// --- Admin Keys ---

func (r *sqlRepo) AddAdminKey(ctx context.Context, pubKey string) error {
	_, err := r.exec(ctx, `INSERT INTO admin_keys (public_key) VALUES (?)
		 ON CONFLICT (public_key) DO NOTHING`, pubKey)
	return err
}

func (r *sqlRepo) ListAdminKeys(ctx context.Context) ([]string, error) {
	rows, err := r.query(ctx, "SELECT public_key FROM admin_keys")
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

func (r *sqlRepo) RemoveAdminKey(ctx context.Context, pubKey string) error {
	_, err := r.exec(ctx, "DELETE FROM admin_keys WHERE public_key = ?", pubKey)
	return err
}

// --- Session Tokens ---

// The two token tables -- session_tokens and api_sessions -- have the same
// shape and the same lifecycle, so the statements are written once here and
// parameterised by table. They differ in exactly one respect, which is the
// point of having both: redeeming a session_tokens row consumes it, while
// looking up an api_sessions row does not. See migrations/sqlite/00006.
const (
	sessionTokenTable = "session_tokens"
	apiSessionTable   = "api_sessions"
)

// insertToken writes a row and sweeps whatever has already expired.
//
// The sweep threshold is now, NOT expiresAt. Sweeping by the new row's own
// expiry would delete every row due to expire before it -- that is, every
// other one outstanding -- so two people logging in at once would lock each
// other out.
//
// The sweep is here rather than on a timer because no long-lived process
// holds a write handle that could run one, and an insert is the only moment
// these tables grow.
func (r *sqlRepo) insertToken(
	ctx context.Context,
	table, tokenHash string,
	identity *models.SessionIdentity,
	now, expiresAt time.Time,
) error {
	if _, err := r.exec(ctx,
		"DELETE FROM "+table+" WHERE expires_at <= ?", now.Unix()); err != nil {
		return fmt.Errorf("sweeping expired rows from %s: %w", table, err)
	}

	isAdmin := 0
	if identity.IsAdmin {
		isAdmin = 1
	}
	if _, err := r.exec(ctx,
		"INSERT INTO "+table+
			" (token_hash, login_name, identity_name, is_admin, client_id, expires_at)"+
			" VALUES (?, ?, ?, ?, ?, ?)",
		tokenHash, identity.LoginName, identity.IdentityName,
		isAdmin, identity.ClientID, expiresAt.Unix()); err != nil {
		return fmt.Errorf("inserting into %s: %w", table, err)
	}
	return nil
}

// scanIdentity reads one identity row.
func scanIdentity(row interface{ Scan(...any) error }) (*models.SessionIdentity, error) {
	var (
		identity models.SessionIdentity
		isAdmin  int64
	)
	err := row.Scan(&identity.LoginName, &identity.IdentityName, &isAdmin, &identity.ClientID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSuchToken
	}
	if err != nil {
		return nil, err
	}
	identity.IsAdmin = isAdmin != 0
	return &identity, nil
}

// MintSessionToken records a token against the identity it was issued for.
//
// tokenHash is a hash, never the token: see the migration.
func (r *sqlRepo) MintSessionToken(
	ctx context.Context,
	tokenHash string,
	identity *models.SessionIdentity,
	now, expiresAt time.Time,
) error {
	return r.insertToken(ctx, sessionTokenTable, tokenHash, identity, now, expiresAt)
}

// RedeemSessionToken consumes a token and reports who it belonged to.
//
// The DELETE ... RETURNING is one statement on purpose. Reading the row and
// then deleting it would let two callers presenting the same token both see
// it before either removed it, which is exactly the replay that "single use"
// is meant to prevent. A single statement makes the delete the thing that
// decides, so only one caller can win. Both backends support RETURNING
// (SQLite since 3.35; modernc.org/sqlite bundles 3.53).
//
// Expiry is applied in the same statement rather than afterwards, so an
// expired token is never redeemable even for the caller that deletes it.
func (r *sqlRepo) RedeemSessionToken(
	ctx context.Context,
	tokenHash string,
	now time.Time,
) (*models.SessionIdentity, error) {
	identity, err := scanIdentity(r.queryRow(ctx,
		`DELETE FROM session_tokens
		  WHERE token_hash = ? AND expires_at > ?
		 RETURNING login_name, identity_name, is_admin, client_id`,
		tokenHash, now.Unix()))
	if err != nil && !errors.Is(err, ErrNoSuchToken) {
		return nil, fmt.Errorf("redeeming session token: %w", err)
	}
	return identity, err
}

// --- API Sessions ---

// CreateAPISession records the credential a session will use from now on.
func (r *sqlRepo) CreateAPISession(
	ctx context.Context,
	tokenHash string,
	identity *models.SessionIdentity,
	now, expiresAt time.Time,
) error {
	return r.insertToken(ctx, apiSessionTable, tokenHash, identity, now, expiresAt)
}

// LookupAPISession returns the identity behind a session credential.
//
// This is a plain SELECT: it does NOT consume the row. A session makes
// several calls over its life, so consuming here would break it on the
// second request. The single-use property stays on the minted token, which
// is where the exposure is -- see migrations/sqlite/00006.
//
// Expiry is applied in the statement so an expired row is never returned,
// even before the next sweep removes it.
func (r *sqlRepo) LookupAPISession(
	ctx context.Context,
	tokenHash string,
	now time.Time,
) (*models.SessionIdentity, error) {
	identity, err := scanIdentity(r.queryRow(ctx,
		`SELECT login_name, identity_name, is_admin, client_id
		   FROM api_sessions
		  WHERE token_hash = ? AND expires_at > ?`,
		tokenHash, now.Unix()))
	if err != nil && !errors.Is(err, ErrNoSuchToken) {
		return nil, fmt.Errorf("looking up api session: %w", err)
	}
	return identity, err
}

// RevokeAPISession drops a session credential.
//
// Called when a session ends, so that a credential does not stay valid for
// the remainder of its TTL after the process holding it is gone. Revoking
// something already absent is not an error: a session that failed early has
// nothing to revoke, and must not report that as a failure.
func (r *sqlRepo) RevokeAPISession(ctx context.Context, tokenHash string) error {
	if _, err := r.exec(ctx,
		"DELETE FROM api_sessions WHERE token_hash = ?", tokenHash); err != nil {
		return fmt.Errorf("revoking api session: %w", err)
	}
	return nil
}

// --- Activity Log ---

// AddActivityEvent appends one audited action. Params is marshaled to JSON
// TEXT (the clients convention); occurred_at is stored as a Unix epoch so one
// scan path serves both backends. On a nil Params, "{}" is stored so the row
// always round-trips to a (possibly empty) object rather than null.
func (r *sqlRepo) AddActivityEvent(ctx context.Context, event *models.ActivityEvent) error {
	params := event.Params
	if params == nil {
		params = map[string]any{}
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshaling activity params: %w", err)
	}
	return r.queryRow(ctx,
		`INSERT INTO activity_log (event_id, actor, occurred_at, params)
		 VALUES (?, ?, ?, ?) RETURNING id`,
		event.EventID, event.Actor, event.OccurredAt.Unix(), string(paramsJSON),
	).Scan(&event.ID)
}

// ListActivity returns a newest-first page of events. A non-positive limit
// falls back to a sane default so a caller cannot ask for an unbounded scan;
// offset is clamped to >= 0. occurred_at ties are broken by id DESC so the
// order is stable across pages even when several events share a second.
func (r *sqlRepo) ListActivity(ctx context.Context, limit, offset int) ([]*models.ActivityEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := r.db.QueryContext(ctx, r.d.rebind(
		`SELECT id, event_id, actor, occurred_at, params
		 FROM activity_log
		 ORDER BY occurred_at DESC, id DESC
		 LIMIT ? OFFSET ?`), limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var list []*models.ActivityEvent
	for rows.Next() {
		e := &models.ActivityEvent{}
		var occurred int64
		var paramsStr string
		if err := rows.Scan(&e.ID, &e.EventID, &e.Actor, &occurred, &paramsStr); err != nil {
			return nil, err
		}
		e.OccurredAt = time.Unix(occurred, 0).UTC()
		_ = json.Unmarshal([]byte(paramsStr), &e.Params)
		list = append(list, e)
	}
	return list, rows.Err()
}

// CountActivity returns the total number of events, for pagination.
func (r *sqlRepo) CountActivity(ctx context.Context) (int, error) {
	var n int
	if err := r.queryRow(ctx, "SELECT COUNT(*) FROM activity_log").Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// DeleteActivityOlderThan removes events older than cutoff and returns how many
// rows were deleted, so the retention loop can log what it pruned.
func (r *sqlRepo) DeleteActivityOlderThan(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := r.exec(ctx,
		"DELETE FROM activity_log WHERE occurred_at < ?", cutoff.Unix())
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil // deletion succeeded; the count is best-effort
	}
	return int(n), nil
}

// --- Access Control Check ---

// HasAccess returns true if clientID is allowed to reach guestID.
// Priority: explicit client rule > group rule > default policy.
func (r *sqlRepo) HasAccess(ctx context.Context, clientID, guestID int64) (bool, error) {
	// 1. Direct client rule
	var exists int
	err := r.queryRow(ctx,
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
	err = r.queryRow(ctx,
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
		err = r.queryRow(ctx,
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

// HasInstanceAccess returns true if clientID is allowed to reach the Proxmox
// node instanceID. Priority: explicit client rule > group rule.
//
// # Why the default policy is not consulted
//
// HasAccess has a third tier: a client named in default_policy reaches
// anything. That tier does not look at its target at all -- it returns true
// for any id, including one that names nothing -- so including it here would
// mean every policy-covered client silently gained a shell on every node the
// moment this table existed.
//
// That is not the same bargain as the guest tier. A default policy is
// standing configuration, often set once and left; an administrator who ran
// `policy add --client alice' months ago was saying something about guests,
// because guests were the only thing it could be about. Reading it now as
// consent to node access would put words in their mouth, and the grant it
// would imply is the broadest one proxpass can give.
//
// So an instance is reachable only when somebody said so explicitly, with
// `access grant --instance'. The cost is that a deployment relying on the
// default policy has to name its nodes; that is the intended cost.
func (r *sqlRepo) HasInstanceAccess(ctx context.Context, clientID, instanceID int64) (bool, error) {
	// 1. Direct client rule
	var exists int
	err := r.queryRow(ctx,
		"SELECT 1 FROM instance_access_rules WHERE type = ? AND subject_id = ? AND instance_id = ? LIMIT 1",
		models.RuleClient, clientID, instanceID).Scan(&exists)
	if err == nil {
		return true, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}

	// 2. Group rules — load the client's group memberships
	var groupsJSON string
	err = r.queryRow(ctx,
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
		err = r.queryRow(ctx,
			"SELECT 1 FROM instance_access_rules WHERE type = ? AND subject_id = ? AND instance_id = ? LIMIT 1",
			models.RuleGroup, gid, instanceID).Scan(&exists)
		if err == nil {
			return true, nil
		}
		if err != sql.ErrNoRows {
			return false, err
		}
	}

	return false, nil
}
