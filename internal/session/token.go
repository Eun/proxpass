package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"proxpass/internal/api"
)

// TokenEnv is the environment variable a session finds its API token in.
//
// It is set by an environment= option on the authorized_keys line of the key
// that authenticated, so sshd puts it in the session's environment itself.
//
// This name must NEVER be added to AcceptEnv in sshd_config: that would let
// the client supply the value instead of receiving it, which is the whole
// attack this design exists to prevent. See docker/sshd_config.d/proxpass.conf.
const TokenEnv = "PROXPASS_SESSION_TOKEN"

// TokenTTL is how long a minted token stays redeemable.
//
// sshd runs AuthorizedKeysCommand during authentication and starts the
// session immediately afterwards, so the gap is well under a second. The
// window only has to cover that handoff plus clock skew between the two
// processes -- which share a container, so there is none to speak of.
//
// It is short because the token sits in the session's environment, and
// anything running as the same uid can read /proc/<pid>/environ. Alias
// sessions all share one uid, so "same uid" includes other people's
// sessions. A token that has already been redeemed is useless anyway: the
// combination of a single use and a short life is what makes the exposure
// survivable rather than either on its own.
const TokenTTL = 60 * time.Second

// tokenBytes is the entropy behind each token. 32 bytes is more than enough
// to make guessing hopeless, and the result still fits comfortably on an
// authorized_keys line.
const tokenBytes = 32

// NewToken returns a fresh token and the hash to store for it.
//
// Only the hash is ever written down; the token itself exists in the
// authorized_keys line sshd reads and in the session's environment, and
// nowhere else. A database reader therefore cannot turn stored state into a
// usable credential, which matters because the database is world-readable in
// the shipped image.
func NewToken() (token, hash string, err error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generating session token: %w", err)
	}
	// Base64url: no padding, and no characters that would need quoting
	// inside the environment="..." option.
	token = base64.RawURLEncoding.EncodeToString(buf)
	return token, HashToken(token), nil
}

// HashToken returns the stored form of a token.
//
// Defined in internal/api because this package already imports that one, so
// putting it here as well would be an import cycle. Re-exported so the
// minting side reads in one piece.
func HashToken(token string) string {
	return api.HashToken(token)
}

// TakeTokenFromEnv returns the minted token and removes it from this
// process's environment.
//
// Unsetting is deliberate. The token arrives in the environment because that
// is the only channel sshd offers between AuthorizedKeysCommand and the
// session, but anything of the same uid can read /proc/<pid>/environ -- and
// every alias session shares one uid. Dropping it as soon as it has been
// read shrinks that window to the startup of this process, after which the
// session holds only the exchanged credential, in memory.
//
// This does not rewrite the kernel's copy of the original environment block,
// so a determined reader of /proc/<pid>/environ can still see the original
// strings; Go's os.Unsetenv only changes what this process will pass on and
// what it reports. The real protection is that the token is single-use and
// is spent microseconds later -- this just avoids handing it to every child
// process the session starts.
func TakeTokenFromEnv() string {
	token := os.Getenv(TokenEnv)
	_ = os.Unsetenv(TokenEnv)
	return token
}

// ValidTokenValue reports whether a token is safe to put in an
// authorized_keys option.
//
// NewToken only ever produces base64url, so this is a guard against a future
// change to the alphabet rather than a check on untrusted input. A token
// containing a quote or a newline would end the option early and let the
// rest be read as further options -- an injection into sshd's own
// configuration for that key.
func ValidTokenValue(token string) bool {
	if token == "" {
		return false
	}
	return !strings.ContainsAny(token, "\"\\\n\r \t")
}
