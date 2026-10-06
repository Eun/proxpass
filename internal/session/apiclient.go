package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"proxpass/internal/api"
)

// ErrNoCredential reports that this process was given no minted token.
//
// That means sshd did not apply the authorized_keys option -- most likely
// PermitUserEnvironment is off, or the session was started by hand. The
// caller decides what to do about it; see cmd/proxpass.
var ErrNoCredential = errors.New("no session token in the environment")

// APIClient talks to the loopback API on behalf of a session.
//
// It holds the exchanged credential in memory and nowhere else. Putting it
// in the environment, a file, or an argv would undo the reason the exchange
// exists: the minted token is readable by anything of the same uid, and the
// credential is supposed to be the thing that is not.
type APIClient struct {
	baseURL string
	http    *http.Client

	// credential is the exchanged token. Empty until Exchange succeeds.
	credential string
}

// apiTimeout bounds a call to the loopback API.
//
// The server is in the same container and every one of these is a local
// database read, so anything approaching this means the directory is wedged.
// A session must not hang forever waiting for it.
const apiTimeout = 10 * time.Second

// NewAPIClient returns a client for the directory API at baseURL.
func NewAPIClient(baseURL string) *APIClient {
	return &APIClient{
		baseURL: baseURL,
		http:    &http.Client{Timeout: apiTimeout},
	}
}

// Exchange spends the minted token for a session credential.
//
// Returns the identity the credential speaks for. After this the client is
// authenticated and the minted token is spent, so this can be called only
// once per session.
func (c *APIClient) Exchange(ctx context.Context, mintedToken string) (*api.Identity, error) {
	if mintedToken == "" {
		return nil, ErrNoCredential
	}

	var out api.SessionCredential
	if err := c.do(ctx, http.MethodPost, "/session/exchange", mintedToken, &out); err != nil {
		return nil, err
	}
	c.credential = out.Token
	return &out.Identity, nil
}

// Revoke gives up the credential.
//
// Best effort: a session is ending either way, and the credential expires on
// its own. The error is returned for logging rather than for handling.
func (c *APIClient) Revoke(ctx context.Context) error {
	if c.credential == "" {
		return nil
	}
	err := c.do(ctx, http.MethodPost, "/session/revoke", c.credential, nil)
	c.credential = ""
	return err
}

// do performs one request with the given bearer token.
func (c *APIClient) do(
	ctx context.Context, method, path, token string, out any,
) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, http.NoBody)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrUnauthorized
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		// The body may carry an Error, but it is deliberately terse and
		// this is a loopback call: the status is the useful part.
		return fmt.Errorf("%s: %s", path, resp.Status)
	}

	if out == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding %s: %w", path, err)
	}
	return nil
}

// maxResponseBytes caps a response body. The API is local and its responses
// are small; a cap stops a wedged server from exhausting the session.
const maxResponseBytes = 4 << 20

// ErrUnauthorized reports a credential the server would not accept.
var ErrUnauthorized = errors.New("the API rejected this session's credential")
