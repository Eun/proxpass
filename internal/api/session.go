package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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

// ExchangeSessionToken spends the minted token for a session credential.
//
// This is the only place the minted token is accepted, and redeeming is what
// authenticates: it is consumed here, so presenting it twice fails. What
// comes back can be presented repeatedly, which is what a session needs --
// browsing and connecting are several calls.
//
// The identity is returned alongside so that the usual startup is one round
// trip rather than an exchange followed immediately by an identity call.
func (h *SessionHandler) ExchangeSessionToken(
	ctx context.Context, _ ExchangeSessionTokenRequestObject,
) (ExchangeSessionTokenResponseObject, error) {
	minted, ok := BearerToken(ctx)
	if !ok {
		return ExchangeSessionToken401JSONResponse{
			UnauthorizedJSONResponse: UnauthorizedJSONResponse{Error: reasonMissingToken},
		}, nil
	}

	identity, err := h.repo.RedeemSessionToken(ctx, HashToken(minted), h.now())
	if errors.Is(err, db.ErrNoSuchToken) {
		return ExchangeSessionToken401JSONResponse{
			UnauthorizedJSONResponse: UnauthorizedJSONResponse{Error: reasonInvalidToken},
		}, nil
	}
	if err != nil {
		// A backend failure is not an authentication failure. Returning
		// the error lets the generated handler answer 500, so an outage
		// does not look to a session like a rejected token.
		return nil, err
	}

	credential, hash, err := NewSessionCredential()
	if err != nil {
		return nil, err
	}
	now := h.now()
	expiresAt := now.Add(SessionCredentialTTL)
	if err := h.repo.CreateAPISession(ctx, hash, identity, now, expiresAt); err != nil {
		return nil, err
	}

	return ExchangeSessionToken200JSONResponse(SessionCredential{
		Token:     credential,
		ExpiresAt: expiresAt,
		Identity:  identityResponse(identity),
	}), nil
}

// RevokeSessionCredential drops the caller's credential.
//
// Idempotent: a credential that was already gone still answers 204. The
// caller is ending either way, and a session that cannot tidy up must not
// fail because of it.
func (h *SessionHandler) RevokeSessionCredential(
	ctx context.Context, _ RevokeSessionCredentialRequestObject,
) (RevokeSessionCredentialResponseObject, error) {
	token, ok := BearerToken(ctx)
	if !ok {
		return RevokeSessionCredential401JSONResponse{
			UnauthorizedJSONResponse: UnauthorizedJSONResponse{Error: reasonMissingToken},
		}, nil
	}
	if err := h.repo.RevokeAPISession(ctx, HashToken(token)); err != nil {
		return nil, err
	}
	return RevokeSessionCredential204Response{}, nil
}

// GetSessionIdentity reports who the calling credential belongs to.
//
// Looking up does NOT consume: a session presents the same credential on
// every call. The single-use property lives on the minted token, which
// ExchangeSessionToken spends.
func (h *SessionHandler) GetSessionIdentity(
	ctx context.Context, _ GetSessionIdentityRequestObject,
) (GetSessionIdentityResponseObject, error) {
	identity, err := h.callerIdentity(ctx)
	if errors.Is(err, errNoCredential) {
		return unauthorized(reasonMissingToken), nil
	}
	if errors.Is(err, db.ErrNoSuchToken) {
		return unauthorized(reasonInvalidToken), nil
	}
	if err != nil {
		return nil, err
	}
	return GetSessionIdentity200JSONResponse(identityResponse(identity)), nil
}

// The terse reasons a 401 body carries. Deliberately uninformative: these
// responses are reachable before a caller is authenticated.
const (
	reasonMissingToken = "missing token"
	reasonInvalidToken = "invalid token"
)

// errNoCredential reports a request that carried no bearer token at all, as
// distinct from one carrying a token the server does not know.
var errNoCredential = errors.New("no session credential")

// callerIdentity resolves the session credential on the request.
//
// Every authenticated endpoint goes through this, so that "who is calling"
// is answered in exactly one place: scope is derived server-side from the
// stored identity, never from anything the caller sends. Endpoints added
// later must use it rather than reading the header themselves.
func (h *SessionHandler) callerIdentity(ctx context.Context) (*models.SessionIdentity, error) {
	token, ok := BearerToken(ctx)
	if !ok {
		return nil, errNoCredential
	}
	return h.repo.LookupAPISession(ctx, HashToken(token), h.now())
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

// SessionCredentialTTL is how long an exchanged credential stays valid.
//
// Unlike the minted token's 60 seconds, this has to cover a whole session: a
// console attach can legitimately sit idle for hours. There is no renewal
// path -- the minted token is spent -- so expiring mid-session would drop a
// working connection, which is why this is generous.
//
// It is bounded rather than unlimited so that a credential belonging to a
// session that died without revoking does not stay usable forever. sshd's
// own ClientAliveInterval/ClientAliveCountMax reap dead sessions long before
// this.
const SessionCredentialTTL = 12 * time.Hour

// NewSessionCredential returns a credential and the hash to store for it.
//
// Same construction as the minted token: 256 bits of randomness, stored only
// as a SHA-256. The database is world-readable in the shipped image, so a
// reader must not be able to turn stored state into a working credential.
func NewSessionCredential() (token, hash string, err error) {
	buf := make([]byte, credentialBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generating session credential: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	return token, HashToken(token), nil
}

// credentialBytes is the entropy behind a session credential.
const credentialBytes = 32

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
