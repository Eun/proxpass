package api

import "strings"

// MaxLoginNameLen bounds a login name.
//
// 32 is the useradd/useradd.8 limit and what utmp records, so a longer name is
// a mistake rather than an intent even though NSS itself would carry it.
const MaxLoginNameLen = 32

// ValidLoginName reports whether name is safe to serve as a Unix login name.
//
// Because proxpass serves users over NSS rather than from /etc/passwd, it is
// not bound by the base image's useradd policy and deliberately accepts more
// than useradd would: mixed case, a leading digit, dots, and non-ASCII are
// all fine. "Tobias", "1st-box" and "tobías" all work.
//
// The restrictions below are NOT stylistic. Each one is a case where the name
// would either fail to round-trip through the lookup path or break the format
// it is written into. All of them were confirmed against the running image.
//
// Note what this does NOT guard against: sshd resolves the login through NSS
// before it authenticates, then uses whatever name came back for the key
// lookup, the argv of AuthorizedKeysCommand and $USER alike. Argv tracing in
// the image confirms that, so a name that truncates during lookup yields a
// confusing alias rather than two disagreeing identities. Rejecting these
// names is a cheap invariant for the paths that pass a name verbatim -- a
// hand-run `proxpass authorized-keys`, or a future nss_http that escapes its
// URLs properly -- not a defense against sshd being misled.
func ValidLoginName(name string) bool {
	if name == "" || len(name) > MaxLoginNameLen {
		return false
	}

	// A colon is the passwd field separator and a newline its record
	// separator, so either one forges a passwd entry. NUL truncates the name
	// for every C consumer, sshd included.
	if strings.ContainsAny(name, ":\n\r\x00") {
		return false
	}

	// nss_http builds its lookup URL by raw concatenation, WITHOUT escaping
	// (providers/http/provider.go: `p.config.URLs.UserName + string(v)`), so
	// the name has to survive as a single URL path segment.
	//
	//   "?" and "#" start the query and the fragment: "to?bias" reaches the
	//   server as "to", so the lookup answers for a different name than the
	//   one asked for -- verified with getent against the image.
	//
	//   "/" adds a path segment and "%" introduces an escape, so "a%2Fb" and
	//   "a/b" both arrive as something other than what was asked for. ".."
	//   makes net/http redirect the request off the route entirely.
	//
	//   A space is legal in a passwd entry but is rejected by the HTTP
	//   request line, so the lookup never happens.
	if strings.ContainsAny(name, "?#/%") || strings.ContainsAny(name, " \t") {
		return false
	}
	if name == "." || name == ".." {
		return false
	}

	// sshd runs `AuthorizedKeysCommand <user>`, and urfave/cli parses a
	// leading "-" as a flag rather than as the username argument: the lookup
	// then reports no keys at all, or acts on an injected flag.
	return !strings.HasPrefix(name, "-")
}
