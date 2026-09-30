package cli

import (
	"fmt"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// ValidatePublicKey checks that raw is exactly one authorized_keys entry.
//
// gossh.ParseAuthorizedKey parses the FIRST line and silently ignores
// everything after it, so validating with it alone lets a single --key smuggle
// additional credentials: the stored value is later printed verbatim to sshd's
// AuthorizedKeysCommand output, where each embedded newline becomes another
// authorized_keys line. The admin would see "1 key(s)" while the account
// actually accepted several, including keys nobody reviewed.
//
// It also rejects authorized_keys option fields (e.g. command=, environment=)
// since proxpass decides what a session may do, not the key.
func ValidatePublicKey(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if key == "" {
		return "", fmt.Errorf("public key must not be empty")
	}

	// Any line break means more than one entry was supplied.
	if strings.ContainsAny(key, "\n\r") {
		return "", fmt.Errorf(
			"public key must be a single line; pass one --key per key")
	}
	// A NUL would truncate the value for anything reading it as a C string.
	if strings.ContainsRune(key, 0) {
		return "", fmt.Errorf("public key must not contain NUL")
	}

	pub, comment, options, rest, err := gossh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}
	if len(rest) > 0 {
		return "", fmt.Errorf(
			"public key must be a single entry; %d trailing bytes found", len(rest))
	}
	if len(options) > 0 {
		return "", fmt.Errorf(
			"authorized_keys options are not allowed on a proxpass key (found %q)",
			strings.Join(options, ","))
	}
	_ = comment
	_ = pub
	return key, nil
}
