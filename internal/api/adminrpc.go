package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"proxpass/internal/db"
	"proxpass/internal/models"
)

// The last of the admin RPC: the two SSH-key operations.
//
// Every db.Repository operation the admin CLI uses now has a typed /v1 REST
// resource (see adminhandlers.go); the old tagged-union allowlist is gone.
// What remains here are the two operations that have no /v1 endpoint on
// purpose: the proxpass SSH key is a root-owned FILE, not a database row (see
// models.sshkey.go and sshkeyops.go). A session cannot read it, so it asks
// `proxpass serve' -- which runs as root -- over this one endpoint, and only
// the public half / a reachability answer come back. Modeling a file read as a
// REST resource bought nothing, so these stayed an RPC.
//
// Every call still requires an admin credential. See adminIdentity.

// AdminRequest is one SSH-key operation.
type AdminRequest struct {
	// Op names the operation: "GetSSHPublicKey" or "CheckInstanceSSHAccess".
	Op string `json:"op"`

	// Params carries the arguments, shaped per operation. Decoded by the
	// handler for Op, so an operation can only ever read the arguments it
	// expects.
	Params json.RawMessage `json:"params,omitempty"`
}

// AdminResponse is the result of one call.
type AdminResponse struct {
	// Result is the operation's return value, absent when it returns only
	// an error.
	Result json.RawMessage `json:"result,omitempty"`

	// Error is the failure message, empty on success. Carried in the body
	// rather than as a status code because these are domain errors the CLI
	// prints verbatim.
	Error string `json:"error,omitempty"`
}

// sshKeyOps is the allowlist: exactly the two SSH-key operations, and nothing
// else. An unknown Op is refused rather than reaching anything.
var sshKeyOps = map[string]func(context.Context, json.RawMessage) (json.RawMessage, error){
	"GetSSHPublicKey":        getSSHPublicKey,
	"CheckInstanceSSHAccess": checkInstanceSSHAccess,
}

// ServeAdminRPC handles POST /admin/rpc, now serving only the SSH-key
// operations. Wired by Handler(); see server.go.
func (s *Server) ServeAdminRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := s.adminIdentity(r); err != nil {
		code := http.StatusUnauthorized
		if errors.Is(err, errNotAdmin) {
			// 403, not 404: the caller authenticated fine, it just is not
			// an administrator. The CLI needs to tell "log in as the admin"
			// from "your token expired".
			code = http.StatusForbidden
		}
		writeAdminError(w, code, err.Error())
		return
	}

	var req AdminRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBody)).
		Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "malformed request")
		return
	}

	op, ok := sshKeyOps[req.Op]
	if !ok {
		s.writeJSON(w, AdminResponse{Error: fmt.Sprintf("unknown operation %q", req.Op)})
		return
	}
	result, err := op(r.Context(), req.Params)
	if err != nil {
		// A domain error is a 200 with an error field: the operation ran and
		// said no. Reserving the status codes for transport problems keeps
		// the CLI's error messages the same as they were.
		s.writeJSON(w, AdminResponse{Error: err.Error()})
		return
	}
	s.writeJSON(w, AdminResponse{Result: result})
}

// maxAdminBody caps a request. The largest legitimate one is a single
// instance for the reachability check.
const maxAdminBody = 1 << 20

func writeAdminError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(AdminResponse{Error: msg})
}

// errNotAdmin reports a valid credential that does not belong to an
// administrator.
var errNotAdmin = errors.New("this operation requires the administrator")

// adminIdentity resolves the caller and insists it is an administrator.
//
// The check is here, server-side, from the stored identity -- never from
// anything the request carries. This is the only thing standing between a
// client session and the SSH-key operations, so it is one function and every
// operation goes through it.
func (s *Server) adminIdentity(r *http.Request) (*models.SessionIdentity, error) {
	req := withBearerToken(r)
	token, ok := BearerToken(req.Context())
	if !ok {
		return nil, errors.New("missing token")
	}
	identity, err := s.repo.LookupAPISession(
		req.Context(), HashToken(token), time.Now())
	if errors.Is(err, db.ErrNoSuchToken) {
		return nil, errors.New("invalid token")
	}
	if err != nil {
		return nil, err
	}
	if !identity.IsAdmin {
		return nil, errNotAdmin
	}
	return identity, nil
}

// decodeParams unmarshals an operation's JSON arguments, tolerating an absent
// body. Used by the SSH-key operations in sshkeyops.go.
func decodeParams(p json.RawMessage, into any) error {
	if len(p) == 0 {
		return nil
	}
	return json.Unmarshal(p, into)
}

// encodeResult marshals an operation's return value. Used by the SSH-key
// operations in sshkeyops.go.
func encodeResult(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}
