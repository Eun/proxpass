// Package version reports the proxpass build version.
//
// The value is set three ways, in order of preference:
//
//  1. A release build sets it via -ldflags "-X proxpass/internal/version.value=v1.2.3"
//     (goreleaser injects the tag; see .goreleaser.yml).
//  2. Otherwise, the module version from the embedded build info -- the version
//     `go install module@vX.Y.Z` recorded, when proxpass was installed that way.
//  3. Otherwise, "dev", so a plain `go build' reports something honest rather
//     than empty.
package version

import "runtime/debug"

// value is overridden at link time by a release build. Keep it a package-level
// var (not a const) so -ldflags -X can set it.
var value string

// String returns the resolved build version.
func String() string {
	if value != "" {
		return value
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}
