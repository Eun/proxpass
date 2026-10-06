package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"proxpass/internal/db"
	"proxpass/internal/models"
)

// SessionHandler implements the generated session API.
//
// It answers from the token the caller presents, never from anything else
// the caller sends: a session has no trustworthy way to say who it is, which
// is the whole reason this API exists. See api/openapi.yaml.
type SessionHandler struct {
	repo   db.Repository
	logger *log.Logger
	now    func() time.Time
}

// NewSessionHandler returns a handler reading identities from repo.
func NewSessionHandler(repo db.Repository, logger *log.Logger) *SessionHandler {
	return &SessionHandler{repo: repo, logger: logger, now: time.Now}
}

// GetHealth answers the liveness probe.
func (h *SessionHandler) GetHealth(
	_ context.Context, _ GetHealthRequestObject,
) (GetHealthResponseObject, error) {
	return GetHealth200TextResponse("ok\n"), nil
}

// GetSessionIdentity reports who the calling token was issued for.
//
// Redeeming is what authenticates: the token is consumed here, so a second
// call with the same one is refused. A session therefore asks once and keeps
// the answer.
func (h *SessionHandler) GetSessionIdentity(
	ctx context.Context, _ GetSessionIdentityRequestObject,
) (GetSessionIdentityResponseObject, error) {
	token, ok := BearerToken(ctx)
	if !ok {
		return unauthorized("missing token"), nil
	}

	identity, err := h.repo.RedeemSessionToken(ctx, HashToken(token), h.now())
	if errors.Is(err, db.ErrNoSuchToken) {
		return unauthorized("invalid token"), nil
	}
	if err != nil {
		// A backend failure is not an authentication failure. Returning
		// the error lets the generated handler answer 500, so an outage
		// does not look to a session like a rejected token.
		return nil, err
	}

	return GetSessionIdentity200JSONResponse(identityResponse(identity)), nil
}

// identityResponse converts the stored identity into the wire shape.
//
// ClientID is a pointer in the generated type because the spec marks it
// optional -- the administrator has no client row. 0 is that absence, so it
// is sent as omitted rather than as a literal zero, which would read as "the
// client with id 0".
func identityResponse(identity *models.SessionIdentity) Identity {
	out := Identity{
		User:        identity.User,
		DisplayName: identity.DisplayName,
		IsAdmin:     identity.IsAdmin,
	}
	if identity.ClientID != 0 {
		id := identity.ClientID
		out.ClientID = &id
	}
	return out
}

func unauthorized(reason string) GetSessionIdentity401JSONResponse {
	return GetSessionIdentity401JSONResponse{
		UnauthorizedJSONResponse: UnauthorizedJSONResponse{Error: reason},
	}
}

// HashToken returns the stored form of a session token.
//
// Plain SHA-256 rather than a password hash on purpose: the input is 256
// bits of machine-generated randomness, not a human-chosen secret, so there
// is no dictionary to slow down and nothing for a work factor to buy. It
// also has to run on every request.
//
// It lives here, not in internal/session, because internal/session already
// imports this package -- the reverse would be an import cycle. The minting
// side calls through to it.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// contextKey is unexported so nothing outside this package can plant a
// bearer token in a context and bypass the middleware.
type contextKey struct{}

var bearerTokenKey contextKey

// BearerToken returns the token the middleware extracted, if any.
func BearerToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(bearerTokenKey).(string)
	return token, ok
}

// withBearerToken parses the Authorization header onto the context.
//
// Only the presence and shape of the header is checked here; whether the
// token means anything is decided by redeeming it, which must happen in the
// handler because it consumes the token. A middleware that validated first
// would have to redeem twice, and the second redemption would fail.
func withBearerToken(r *http.Request) *http.Request {
	const prefix = "Bearer "

	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) ||
		!strings.EqualFold(header[:len(prefix)], prefix) {
		return r
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), bearerTokenKey, token))
}
