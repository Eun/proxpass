package api

import (
	"strings"
)

// SettingsSnapshot is the effective serve configuration the admin Settings view
// reads: the flags/environment serve was started with, captured at startup.
//
// It is a plain value, built by cmd/proxpass from the parsed flags and handed
// to the SessionHandler (WithSettings). The handler turns it into the read-only
// list keyed by environment variable, masking the secret-bearing fields so a
// token or a database password never leaves the process in cleartext --
// masking is done HERE, in the backend, not in the browser.
//
// PublicEndpoint is intentionally NOT a field: it is a stored setting, read
// from the database at request time (it can change without a restart, unlike
// the rest), so ListSettings fetches it from the repo.
type SettingsSnapshot struct {
	Data              string // --data (PROXPASS_DATA): sqlite path or postgres DSN
	LogLevel          string // --log-level
	DiscoveryInterval string // --discovery-interval
	Listen            string // --listen (the one API listener)
	AdminKey          string // --admin-key: a PUBLIC key, so shown in cleartext
	NSSTokenSet       bool   // whether --nss-token was supplied (secret)
	RESTAPITokenSet   bool   // whether --rest-api-token was supplied (secret)
	ActivityRetention string // --activity-retention (0 = logging disabled)
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

// buildSettings turns the snapshot (plus the stored public endpoint) into the
// read-only list the Settings view shows. Each entry is keyed by the
// environment variable that controls it. The two tokens and the database
// password are masked here; the admin key is a PUBLIC key, so it is shown as
// given.
func buildSettings(s *SettingsSnapshot, publicEndpoint string) []SettingEntry {
	entry := func(envVar, value string) SettingEntry {
		return SettingEntry{Key: envVar, Value: value}
	}
	return []SettingEntry{
		entry("PROXPASS_PUBLIC_ENDPOINT", valueOrUnset(publicEndpoint)),
		entry("PROXPASS_DATA", maskDataSource(s.Data)),
		entry("PROXPASS_LOG_LEVEL", s.LogLevel),
		entry("PROXPASS_DISCOVERY_INTERVAL", s.DiscoveryInterval),
		entry("PROXPASS_LISTEN", s.Listen),
		entry("PROXPASS_ADMIN_KEY", valueOrUnset(s.AdminKey)),
		entry("PROXPASS_NSS_TOKEN", maskSecretSet(s.NSSTokenSet)),
		entry("PROXPASS_REST_API_TOKEN", maskSecretSet(s.RESTAPITokenSet)),
		entry("PROXPASS_ACTIVITY_RETENTION", activityRetentionDisplay(s.ActivityRetention)),
	}
}

// activityRetentionDisplay renders the retention value, making the "disabled"
// case explicit rather than showing a bare "0s".
func activityRetentionDisplay(v string) string {
	if v == "" || v == "0s" || v == "0" {
		return "0s (activity logging disabled)"
	}
	return v
}

// valueOrUnset renders an empty optional value as an explicit "(not set)" so a
// blank cell does not read as "unknown".
func valueOrUnset(v string) string {
	if v == "" {
		return "(not set)"
	}
	return v
}
