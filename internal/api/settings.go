package api

import (
	"strings"
)

// SettingsSnapshot is the effective serve configuration the admin Settings view
// reads: the flags/environment serve was started with, captured at startup.
//
// It is a plain value, built by cmd/proxpass from the parsed flags and handed
// to the SessionHandler (WithSettings). The handler turns it into the read-only
// Setting list, masking the secret-bearing fields so a token or a database
// password never leaves the process in cleartext -- masking is done HERE, in
// the backend, not in the browser.
//
// PublicEndpoint is intentionally NOT a field: it is a stored setting, read
// from the database at request time (it can change without a restart, unlike
// the rest), so ListSettings fetches it from the repo.
type SettingsSnapshot struct {
	Data              string // --data (PROXPASS_DATA): sqlite path or postgres DSN
	LogLevel          string // --log-level
	DiscoveryInterval string // --discovery-interval
	Listen            string // --listen (loopback API listener)
	RESTAPIListen     string // --rest-api-listen (second listener; may be empty)
	AdminKeySet       bool   // whether --admin-key was supplied
	NSSTokenSet       bool   // whether --nss-token was supplied (secret)
	RESTAPITokenSet   bool   // whether --rest-api-token was supplied (secret)
}

// maskSecretSet renders a secret as its set/unset status without revealing it.
// A set secret shows a fixed bullet string so its length is not leaked either.
func maskSecretSet(set bool) string {
	if set {
		return "•••••••• (set)"
	}
	return "(not set)"
}

// maskDataSource masks the password in a postgres DSN while leaving the rest
// readable, and returns a plain path unchanged (a sqlite file path is not a
// secret). So postgres://user:pass@host/db becomes postgres://user:***@host/db.
func maskDataSource(data string) string {
	if !strings.HasPrefix(data, "postgres://") && !strings.HasPrefix(data, "postgresql://") {
		return data // sqlite path: not sensitive
	}
	// Mask the password between the first ':' after '//' and the '@'.
	scheme := data[:strings.Index(data, "//")+2]
	rest := data[len(scheme):]
	at := strings.Index(rest, "@")
	if at < 0 {
		return data // no credentials portion
	}
	creds := rest[:at]
	tail := rest[at:]
	if colon := strings.Index(creds, ":"); colon >= 0 {
		creds = creds[:colon] + ":***"
	}
	return scheme + creds + tail
}

func strPtrSettings(s string) *string { return &s }
func boolPtrSettings(b bool) *bool    { return &b }

// buildSettings turns the snapshot (plus the stored public endpoint) into the
// read-only Setting list the Settings view shows. Secrets are masked here.
func buildSettings(s *SettingsSnapshot, publicEndpoint string) []Setting {
	entry := func(key, value, source string, secret bool) Setting {
		return Setting{
			Key:    key,
			Value:  value,
			Source: strPtrSettings(source),
			Secret: boolPtrSettings(secret),
		}
	}
	return []Setting{
		entry("public_endpoint", publicEndpoint, "PROXPASS_PUBLIC_ENDPOINT", false),
		entry("data", maskDataSource(s.Data), "PROXPASS_DATA", false),
		entry("log_level", s.LogLevel, "PROXPASS_LOG_LEVEL", false),
		entry("discovery_interval", s.DiscoveryInterval, "PROXPASS_DISCOVERY_INTERVAL", false),
		entry("listen", s.Listen, "PROXPASS_LISTEN", false),
		entry("rest_api_listen", valueOrUnset(s.RESTAPIListen), "PROXPASS_REST_API_LISTEN", false),
		entry("admin_key", maskSecretSet(s.AdminKeySet), "PROXPASS_ADMIN_KEY", false),
		entry("nss_token", maskSecretSet(s.NSSTokenSet), "PROXPASS_NSS_TOKEN", true),
		entry("rest_api_token", maskSecretSet(s.RESTAPITokenSet), "PROXPASS_REST_API_TOKEN", true),
	}
}

// valueOrUnset renders an empty optional value as an explicit "(not set)" so a
// blank cell does not read as "unknown".
func valueOrUnset(v string) string {
	if v == "" {
		return "(not set)"
	}
	return v
}
