package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"proxpass/internal/api"
	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/sshhostkey"
)

// AdminRepository is a db.Repository served by the typed /v1 admin REST API.
//
// The admin CLI is a large surface -- 21 commands over the repository
// interface -- and every one of them already speaks db.Repository.
// Implementing the interface rather than rewriting the CLI means the commands
// are untouched, so this change moves WHERE the data lives without altering
// what any command does. That is the only version of this change that can be
// reviewed with confidence.
//
// Each method now calls the matching generated client operation over /v1 and
// translates between the wire schemas (package api) and the storage models
// (package models). A non-2xx carries the server's Error.error message, so the
// CLI prints the same domain errors it printed before (e.g. "a client with
// that name exists").
//
// Only the methods the admin CLI actually uses are implemented. The rest
// panic, loudly and on purpose: they are unreachable from an admin session,
// and a silent zero value would be a correctness bug waiting to happen. See
// unsupported.
//
// The two SSH-key methods (SSHPublicKey / CheckInstanceSSHAccess) are NOT
// db.Repository methods and have no /v1 endpoint: the deployment key is a
// root-owned file, not a database row. They stay on the one remaining
// /admin/rpc operation each; see apiclient.go's postJSON and api/adminrpc.go.
type AdminRepository struct {
	// client keeps the raw APIClient for the two SSH-key operations, which
	// are not part of the typed /v1 surface (see the SSH-key section below).
	client *APIClient

	// api is the generated typed client for every /v1 admin operation. It is
	// built from the APIClient's base URL and HTTP client, with a request
	// editor that adds the exchanged bearer credential.
	api *api.ClientWithResponses
}

// NewAdminRepository returns a repository backed by the admin API.
func NewAdminRepository(client *APIClient) *AdminRepository {
	// The bearer credential is set when Exchange succeeds, which happens
	// before any repository call. Read it from the APIClient at request time
	// rather than capturing it here, so a credential minted after
	// construction is still used.
	bearer := func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+client.credential)
		return nil
	}
	gen, err := api.NewClientWithResponses(client.baseURL,
		api.WithHTTPClient(client.http),
		api.WithRequestEditorFn(bearer))
	if err != nil {
		// NewClientWithResponses only fails on a malformed server URL, which
		// is a programming error here: the base URL is the loopback address
		// this process was given, not user input.
		panic("session: building the admin API client: " + err.Error())
	}
	return &AdminRepository{client: client, api: gen}
}

// Close is a no-op: there is no handle to close.
func (r *AdminRepository) Close() error { return nil }

// apiError turns a non-2xx response into the error the CLI expects.
//
// 401 and 403 become the session's sentinels so callers can tell "your token
// expired" from "log in as the administrator" -- the admin CLI and its tests
// match on these. Every other status carries the server's Error.error
// message, which is the repository's own domain error, so the CLI prints what
// it always printed.
func apiError(status int, body []byte) error {
	switch status {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrNotAdmin
	}
	var e api.Error
	if err := json.Unmarshal(body, &e); err == nil && e.Error != "" {
		return errors.New(e.Error)
	}
	return fmt.Errorf("admin API: unexpected status %d", status)
}

// ok reports whether status is 2xx.
func ok(status int) bool { return status >= 200 && status <= 299 }

// mapList turns a list response into mapped models, or the server's error.
//
// The five list operations differ only in their element type and mapper --
// check the status, then map each element -- so the shared shape lives here
// once rather than being repeated five times (which dupl rightly rejects).
// The caller has already handled a transport error, so items is the typed 200
// body (nil on a non-2xx) and status/body classify a failure.
func mapList[S, M any](
	items *[]S, status int, body []byte, conv func(*S) *M,
) ([]*M, error) {
	if status != http.StatusOK {
		return nil, apiError(status, body)
	}
	out := make([]*M, 0, len(*items))
	for i := range *items {
		out = append(out, conv(&(*items)[i]))
	}
	return out, nil
}

// --- Proxmox instances ---

func (r *AdminRepository) AddProxmoxInstance(ctx context.Context, inst *models.ProxmoxInstance) error {
	// The database assigns the id, so the stored row comes back and is
	// copied over the caller's struct -- the CLI reads inst.ID afterwards.
	resp, err := r.api.AddInstanceWithResponse(ctx, toAPIInstance(inst))
	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusCreated {
		return apiError(resp.StatusCode(), resp.Body)
	}
	*inst = *fromAPIInstance(resp.JSON201)
	return nil
}

func (r *AdminRepository) ListProxmoxInstances(ctx context.Context) ([]*models.ProxmoxInstance, error) {
	resp, err := r.api.ListInstancesWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	return mapList(resp.JSON200, resp.StatusCode(), resp.Body, fromAPIInstance)
}

func (r *AdminRepository) UpdateProxmoxInstance(ctx context.Context, inst *models.ProxmoxInstance) error {
	// The stored row comes back and is copied over the caller's struct, so
	// that a field the server normalized -- the API URL loses a trailing
	// slash -- is what the caller then prints.
	resp, err := r.api.UpdateInstanceWithResponse(ctx, inst.ID, toAPIInstance(inst))
	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusOK {
		return apiError(resp.StatusCode(), resp.Body)
	}
	*inst = *fromAPIInstance(resp.JSON200)
	return nil
}

func (r *AdminRepository) RemoveProxmoxInstance(ctx context.Context, id int64) error {
	resp, err := r.api.RemoveInstanceWithResponse(ctx, id)
	if err != nil {
		return err
	}
	if !ok(resp.StatusCode()) {
		return apiError(resp.StatusCode(), resp.Body)
	}
	return nil
}

// --- Clients ---

func (r *AdminRepository) AddClient(ctx context.Context, client *models.Client) error {
	resp, err := r.api.AddClientWithResponse(ctx, toAPIClient(client))
	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusCreated {
		return apiError(resp.StatusCode(), resp.Body)
	}
	*client = *fromAPIClient(resp.JSON201)
	return nil
}

func (r *AdminRepository) ListClients(ctx context.Context) ([]*models.Client, error) {
	resp, err := r.api.ListClientsWithResponse(ctx, nil)
	if err != nil {
		return nil, err
	}
	return mapList(resp.JSON200, resp.StatusCode(), resp.Body, fromAPIClient)
}

func (r *AdminRepository) RemoveClient(ctx context.Context, id int64) error {
	resp, err := r.api.RemoveClientWithResponse(ctx, id)
	if err != nil {
		return err
	}
	if !ok(resp.StatusCode()) {
		return apiError(resp.StatusCode(), resp.Body)
	}
	return nil
}

// GetClientByName looks the client up by name through the list endpoint's
// ?name= form. A name that matches nothing is a 404, which becomes a non-nil
// error here -- the same shape the old RPC produced, where the repository's
// sql.ErrNoRows crossed back as an error rather than a nil client. The two CLI
// callers both treat a non-nil error as "not found", so the message differs
// but the behavior does not.
func (r *AdminRepository) GetClientByName(ctx context.Context, name string) (*models.Client, error) {
	resp, err := r.api.ListClientsWithResponse(ctx, &api.ListClientsParams{Name: &name})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, apiError(resp.StatusCode(), resp.Body)
	}
	list := *resp.JSON200
	if len(list) == 0 {
		return nil, fmt.Errorf("no such client")
	}
	return fromAPIClient(&list[0]), nil
}

// --- Groups ---

func (r *AdminRepository) AddGroup(ctx context.Context, group *models.Group) error {
	resp, err := r.api.AddGroupWithResponse(ctx, toAPIGroup(group))
	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusCreated {
		return apiError(resp.StatusCode(), resp.Body)
	}
	*group = *fromAPIGroup(resp.JSON201)
	return nil
}

func (r *AdminRepository) ListGroups(ctx context.Context) ([]*models.Group, error) {
	resp, err := r.api.ListGroupsWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	return mapList(resp.JSON200, resp.StatusCode(), resp.Body, fromAPIGroup)
}

func (r *AdminRepository) RemoveGroup(ctx context.Context, id int64) error {
	resp, err := r.api.RemoveGroupWithResponse(ctx, id)
	if err != nil {
		return err
	}
	if !ok(resp.StatusCode()) {
		return apiError(resp.StatusCode(), resp.Body)
	}
	return nil
}

// --- Guests ---

func (r *AdminRepository) ListGuests(ctx context.Context) ([]*models.Guest, error) {
	resp, err := r.api.ListGuestsWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	return mapList(resp.JSON200, resp.StatusCode(), resp.Body, fromAPIGuestRow)
}

// --- Access rules ---

func (r *AdminRepository) ListAccessRules(ctx context.Context) ([]*models.AccessRuleRow, error) {
	resp, err := r.api.ListAccessRulesWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	return mapList(resp.JSON200, resp.StatusCode(), resp.Body, fromAPIAccessRuleRow)
}

func (r *AdminRepository) GrantClientAccess(ctx context.Context, clientID int64, guestIDs []int64) error {
	return r.grantAccess(ctx, api.RuleTypeClient, clientID, guestIDs)
}

func (r *AdminRepository) GrantGroupAccess(ctx context.Context, groupID int64, guestIDs []int64) error {
	return r.grantAccess(ctx, api.RuleTypeGroup, groupID, guestIDs)
}

func (r *AdminRepository) grantAccess(
	ctx context.Context, kind api.RuleType, subjectID int64, guestIDs []int64,
) error {
	resp, err := r.api.GrantAccessWithResponse(ctx, api.GuestAccessChange{
		Subject:  api.AccessSubject{Kind: kind, ID: subjectID},
		GuestIds: guestIDs,
	})
	if err != nil {
		return err
	}
	if !ok(resp.StatusCode()) {
		return apiError(resp.StatusCode(), resp.Body)
	}
	return nil
}

func (r *AdminRepository) RevokeClientAccess(ctx context.Context, clientID, guestID int64) error {
	return r.revokeAccess(ctx, api.RuleTypeClient, clientID, guestID)
}

func (r *AdminRepository) RevokeGroupAccess(ctx context.Context, groupID, guestID int64) error {
	return r.revokeAccess(ctx, api.RuleTypeGroup, groupID, guestID)
}

func (r *AdminRepository) revokeAccess(
	ctx context.Context, kind api.RuleType, subjectID, guestID int64,
) error {
	resp, err := r.api.RevokeAccessWithResponse(ctx, api.GuestAccessChange{
		Subject:  api.AccessSubject{Kind: kind, ID: subjectID},
		GuestIds: []int64{guestID},
	})
	if err != nil {
		return err
	}
	if !ok(resp.StatusCode()) {
		return apiError(resp.StatusCode(), resp.Body)
	}
	return nil
}

// --- Instance access rules ---

func (r *AdminRepository) ListInstanceAccessRules(
	ctx context.Context,
) ([]*models.InstanceAccessRuleRow, error) {
	resp, err := r.api.ListInstanceAccessRulesWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	return mapList(resp.JSON200, resp.StatusCode(), resp.Body, fromAPIInstanceAccessRuleRow)
}

func (r *AdminRepository) GrantClientInstanceAccess(
	ctx context.Context, clientID int64, instanceIDs []int64,
) error {
	return r.grantInstanceAccess(ctx, api.RuleTypeClient, clientID, instanceIDs)
}

func (r *AdminRepository) GrantGroupInstanceAccess(
	ctx context.Context, groupID int64, instanceIDs []int64,
) error {
	return r.grantInstanceAccess(ctx, api.RuleTypeGroup, groupID, instanceIDs)
}

func (r *AdminRepository) grantInstanceAccess(
	ctx context.Context, kind api.RuleType, subjectID int64, instanceIDs []int64,
) error {
	resp, err := r.api.GrantInstanceAccessWithResponse(ctx, api.InstanceAccessChange{
		Subject:     api.AccessSubject{Kind: kind, ID: subjectID},
		InstanceIds: instanceIDs,
	})
	if err != nil {
		return err
	}
	if !ok(resp.StatusCode()) {
		return apiError(resp.StatusCode(), resp.Body)
	}
	return nil
}

func (r *AdminRepository) RevokeClientInstanceAccess(
	ctx context.Context, clientID, instanceID int64,
) error {
	return r.revokeInstanceAccess(ctx, api.RuleTypeClient, clientID, instanceID)
}

func (r *AdminRepository) RevokeGroupInstanceAccess(
	ctx context.Context, groupID, instanceID int64,
) error {
	return r.revokeInstanceAccess(ctx, api.RuleTypeGroup, groupID, instanceID)
}

func (r *AdminRepository) revokeInstanceAccess(
	ctx context.Context, kind api.RuleType, subjectID, instanceID int64,
) error {
	resp, err := r.api.RevokeInstanceAccessWithResponse(ctx, api.InstanceAccessChange{
		Subject:     api.AccessSubject{Kind: kind, ID: subjectID},
		InstanceIds: []int64{instanceID},
	})
	if err != nil {
		return err
	}
	if !ok(resp.StatusCode()) {
		return apiError(resp.StatusCode(), resp.Body)
	}
	return nil
}

// --- Default policy ---

func (r *AdminRepository) SetDefaultPolicy(ctx context.Context, policy *models.DefaultAccessPolicy) error {
	resp, err := r.api.SetDefaultPolicyWithResponse(ctx, toAPIDefaultPolicy(policy))
	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusOK {
		return apiError(resp.StatusCode(), resp.Body)
	}
	return nil
}

func (r *AdminRepository) GetDefaultPolicy(ctx context.Context) (*models.DefaultAccessPolicy, error) {
	resp, err := r.api.GetDefaultPolicyWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, apiError(resp.StatusCode(), resp.Body)
	}
	return fromAPIDefaultPolicy(resp.JSON200), nil
}

// --- Settings ---

func (r *AdminRepository) SetSetting(ctx context.Context, key, value string) error {
	resp, err := r.api.SetSettingWithResponse(ctx, key, api.SettingValue{Value: value})
	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusOK {
		return apiError(resp.StatusCode(), resp.Body)
	}
	return nil
}

func (r *AdminRepository) GetSetting(ctx context.Context, key string) (string, error) {
	resp, err := r.api.GetSettingWithResponse(ctx, key)
	if err != nil {
		return "", err
	}
	if resp.StatusCode() != http.StatusOK {
		return "", apiError(resp.StatusCode(), resp.Body)
	}
	return resp.JSON200.Value, nil
}

// --- Admin keys ---

func (r *AdminRepository) AddAdminKey(ctx context.Context, pubKey string) error {
	resp, err := r.api.AddAdminKeyWithResponse(ctx, api.AdminKey{PublicKey: pubKey})
	if err != nil {
		return err
	}
	if !ok(resp.StatusCode()) {
		return apiError(resp.StatusCode(), resp.Body)
	}
	return nil
}

func (r *AdminRepository) ListAdminKeys(ctx context.Context) ([]string, error) {
	resp, err := r.api.ListAdminKeysWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, apiError(resp.StatusCode(), resp.Body)
	}
	return resp.JSON200.PublicKeys, nil
}

func (r *AdminRepository) RemoveAdminKey(ctx context.Context, pubKey string) error {
	resp, err := r.api.RemoveAdminKeyWithResponse(ctx, api.AdminKey{PublicKey: pubKey})
	if err != nil {
		return err
	}
	if !ok(resp.StatusCode()) {
		return apiError(resp.StatusCode(), resp.Body)
	}
	return nil
}

// --- SSH key file ---
//
// These two are NOT db.Repository methods: the proxpass SSH key is a
// root-owned file the session cannot read, so the work happens in `proxpass
// serve' (root) and only the public half / a reachability answer come back.
// They satisfy cli.SSHKeyService, which the admin CLI calls instead of
// reading the file itself.
//
// They have no /v1 endpoint -- a file is not a REST resource and its public
// half is not a schema worth generating -- so they remain the only two
// operations on the retained /admin/rpc endpoint. See api/adminrpc.go.

// sshRPC performs one /admin/rpc operation and decodes its result. It is the
// last caller of the RPC endpoint, kept only for the two SSH-key operations.
func (r *AdminRepository) sshRPC(ctx context.Context, op string, params, result any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("encoding %s: %w", op, err)
		}
		raw = b
	}

	var resp api.AdminResponse
	if err := r.client.postJSON(ctx, "/admin/rpc",
		api.AdminRequest{Op: op, Params: raw}, &resp); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	if result == nil || len(resp.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(resp.Result, result); err != nil {
		return fmt.Errorf("decoding %s: %w", op, err)
	}
	return nil
}

// SSHPublicKey returns the authorized_keys line for the deployment key, or ""
// when the deployment has no key. The second value is the key's path, for the
// CLI's "none at <path>" message.
func (r *AdminRepository) SSHPublicKey(ctx context.Context) (pub, path string, err error) {
	var out struct {
		Key  string `json:"key"`
		Path string `json:"path"`
	}
	if err := r.sshRPC(ctx, "GetSSHPublicKey", nil, &out); err != nil {
		return "", "", err
	}
	return out.Key, out.Path, nil
}

// CheckInstanceSSHAccess reports whether the deployment key opens a session on
// the instance's host. A non-nil error is the reason it does not, suitable for
// printing; a nil error means the host is reachable.
//
// An unverifiable host key is rebuilt as a *sshhostkey.ErrNoFingerprint so the
// CLI's errors.As check still recognizes the fatal case across the API: the
// serve side carries the host and presented fingerprint as structured data
// rather than as a plain string, because the message alone cannot be
// re-typed.
func (r *AdminRepository) CheckInstanceSSHAccess(ctx context.Context, inst *models.ProxmoxInstance) error {
	var out struct {
		OK            bool   `json:"ok"`
		Err           string `json:"err"`
		NoFingerprint *struct {
			Host        string `json:"host"`
			Fingerprint string `json:"fingerprint"`
		} `json:"no_fingerprint"`
	}
	if err := r.sshRPC(ctx, "CheckInstanceSSHAccess",
		map[string]any{"instance": inst}, &out); err != nil {
		return err
	}
	if out.OK {
		return nil
	}
	if out.NoFingerprint != nil {
		return &sshhostkey.ErrNoFingerprint{
			Host:        out.NoFingerprint.Host,
			Fingerprint: out.NoFingerprint.Fingerprint,
		}
	}
	return errors.New(out.Err)
}

// --- Not reachable from a session ---
//
// These exist only to satisfy db.Repository. A session never calls them: the
// guest lookup is served by the Directory, the discovery writes belong to the
// discovery loop, the access checks are answered by `proxpass serve', and the
// token methods belong to the process that holds the real database. None has a
// /v1 endpoint on the admin surface, and the admin CLI never calls any of
// them. They panic rather than return a zero value, so a future caller finds
// out immediately instead of silently getting "no such row", a false access
// answer, or a token that was never stored.

func (r *AdminRepository) GetGuestByID(context.Context, int64) (*models.Guest, error) {
	panic(unsupported("GetGuestByID"))
}

func (r *AdminRepository) UpsertGuest(context.Context, *models.Guest) error {
	panic(unsupported("UpsertGuest"))
}

func (r *AdminRepository) RemoveGuestsNotIn(context.Context, int64, []int) (int, error) {
	panic(unsupported("RemoveGuestsNotIn"))
}

func (r *AdminRepository) UpdateClient(context.Context, *models.Client) error {
	panic(unsupported("UpdateClient"))
}

func (r *AdminRepository) UpdateGroup(context.Context, *models.Group) error {
	panic(unsupported("UpdateGroup"))
}

func (r *AdminRepository) HasAccess(context.Context, int64, int64) (bool, error) {
	panic(unsupported("HasAccess"))
}

func (r *AdminRepository) HasInstanceAccess(context.Context, int64, int64) (bool, error) {
	panic(unsupported("HasInstanceAccess"))
}

func (r *AdminRepository) MintSessionToken(
	context.Context, string, *models.SessionIdentity, time.Time, time.Time,
) error {
	panic(unsupported("MintSessionToken"))
}

func (r *AdminRepository) RedeemSessionToken(
	context.Context, string, time.Time,
) (*models.SessionIdentity, error) {
	panic(unsupported("RedeemSessionToken"))
}

func (r *AdminRepository) CreateAPISession(
	context.Context, string, *models.SessionIdentity, time.Time, time.Time,
) error {
	panic(unsupported("CreateAPISession"))
}

func (r *AdminRepository) LookupAPISession(
	context.Context, string, time.Time,
) (*models.SessionIdentity, error) {
	panic(unsupported("LookupAPISession"))
}

func (r *AdminRepository) RevokeAPISession(context.Context, string) error {
	panic(unsupported("RevokeAPISession"))
}

func (r *AdminRepository) AddActivityEvent(context.Context, *models.ActivityEvent) error {
	panic(unsupported("AddActivityEvent"))
}

func (r *AdminRepository) ListActivity(context.Context, int, int) ([]*models.ActivityEvent, error) {
	panic(unsupported("ListActivity"))
}

func (r *AdminRepository) CountActivity(context.Context) (int, error) {
	panic(unsupported("CountActivity"))
}

func (r *AdminRepository) DeleteActivityOlderThan(context.Context, time.Time) (int, error) {
	panic(unsupported("DeleteActivityOlderThan"))
}

// unsupported explains why a method is missing rather than just that it is.
func unsupported(method string) string {
	return "session: " + method + " is not available over the admin API; " +
		"a session does not hold the database, and this method is not one " +
		"the admin CLI uses"
}

// AdminRepository must satisfy the interface the CLI takes.
var _ db.Repository = (*AdminRepository)(nil)
