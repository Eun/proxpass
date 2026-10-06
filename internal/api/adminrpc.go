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

// The admin API: one endpoint, one operation name per Repository method.
//
// This is deliberately an RPC rather than a REST resource tree. The caller is
// the admin CLI, which already speaks db.Repository -- it is not a general
// client, and nothing but proxpass will ever call this. Mirroring the
// interface means the CLI keeps working untouched, so the change is "where
// does a repository live", not "rewrite every command". A REST design would
// have meant ~20 hand-shaped routes and rewriting all 50 call sites, each an
// opportunity to quietly change behavior.
//
// It is NOT a way to run arbitrary SQL: the operation name is matched against
// a fixed list below, and anything else is refused. The set of things an
// administrator can do is exactly the set of methods proxpass already
// implements.
//
// Every call requires an admin credential. See adminIdentity.

// AdminRequest is one Repository call.
type AdminRequest struct {
	// Op names the Repository method, e.g. "ListClients".
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
	// rather than as a status code because these are domain errors -- "a
	// client with that name exists" -- and the CLI prints them verbatim.
	Error string `json:"error,omitempty"`
}

// ServeAdminRPC handles POST /admin/rpc.
//
// Written by hand rather than generated: the request body is a tagged union,
// which OpenAPI describes badly and oapi-codegen generates worse. The spec
// documents the endpoint and says so.
func (s *Server) ServeAdminRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := s.adminIdentity(r); err != nil {
		code := http.StatusUnauthorized
		if errors.Is(err, errNotAdmin) {
			// 403, not 404: the caller authenticated fine, it just is not
			// an administrator. There is nothing to hide here -- whether
			// an admin API exists is not a secret, and the CLI needs to
			// tell "log in as the admin" from "your token expired".
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

	result, err := s.dispatchAdmin(r.Context(), &req)
	if err != nil {
		// A domain error is a 200 with an error field: the call reached the
		// repository and the repository said no. Reserving the status codes
		// for transport problems keeps the CLI's error messages the same as
		// they were when it held the database itself.
		s.writeJSON(w, AdminResponse{Error: err.Error()})
		return
	}
	s.writeJSON(w, AdminResponse{Result: result})
}

// maxAdminBody caps a request. The largest legitimate one is a handful of
// SSH public keys.
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
// client session and every write in the system, so it is one function and
// every operation goes through it.
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

// dispatchAdmin routes one operation.
//
// The switch is the allowlist: an unknown Op is refused rather than reaching
// anything. Adding a Repository method does not silently expose it.
func (s *Server) dispatchAdmin(ctx context.Context, req *AdminRequest) (json.RawMessage, error) {
	h, ok := adminOps[req.Op]
	if !ok {
		return nil, fmt.Errorf("unknown operation %q", req.Op)
	}
	return h(ctx, s.repo, req.Params)
}
