// Package webui serves the proxpass admin single-page app.
//
// The built UI (index.html + compiled CSS + vendored JS) lives in dist/ and is
// compiled into the binary with //go:embed, so the single proxpass binary
// serves the whole admin UI with no external files and no runtime filesystem
// dependency. dist/ is produced by the `frontend' mise task (Tailwind
// standalone CLI -- no Node.js); see mise.toml.
//
// Like internal/guesthelper, dist/ is committed to the repository: a fresh
// checkout compiles and `go test ./...' runs without first building the
// frontend. The committed dist is a real build produced deterministically by
// the `frontend' mise task from the pinned Tailwind CLI + vendored JS, so it is
// reproducible -- re-running the task and committing the result is a no-op when
// the sources are unchanged. IsPlaceholder reports whether what is embedded is
// a build-time stub rather than a real build, which a test asserts against so a
// placeholder can never be shipped by accident.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// dist holds the built admin UI. The patterns include the dotfile placeholder
// marker explicitly (//go:embed ignores names beginning with '.' or '_' unless
// named or matched via 'all:').
//
//go:embed all:dist
var dist embed.FS

// placeholderMarker is a sentinel string present in the committed placeholder
// index.html and absent from a real build. A real Tailwind/SPA build never
// contains it.
const placeholderMarker = "PROXPASS_WEBUI_PLACEHOLDER"

// FS returns the embedded dist/ tree rooted so that "index.html",
// "assets/app.css", etc. resolve directly.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// Unreachable: dist is embedded at compile time, so the subtree
		// always exists. Panicking here would only fire on a programming
		// error in this package.
		panic("webui: embedded dist subtree missing: " + err.Error())
	}
	return sub
}

// Handler serves the admin UI as a static file tree. It is mounted under a
// prefix by the caller (see internal/api/server.go), which strips the prefix
// before delegating here, so this handler always sees root-relative paths.
//
// A request for "/" (or a path with no file) serves index.html. Unknown paths
// return 404 from the underlying file server; the SPA uses hash-based views, so
// there is no HTML5 history fallback to emulate.
func Handler() http.Handler {
	// http.FileServer already serves index.html for "/" and the built assets
	// for their own paths, and returns 404 for a genuinely missing file. A
	// bare "" path (which chi's NotFound can produce) is normalized to "/" so
	// it maps to the index rather than being rejected; "/index.html" itself is
	// not rewritten, so FileServer's canonicalizing redirect never fires.
	fileServer := http.FileServer(http.FS(FS()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

// IsPlaceholder reports whether the embedded UI is the committed placeholder
// rather than a real build. serve uses this to warn (and to let tests assert
// the real UI was built) instead of silently serving a stub.
func IsPlaceholder() bool {
	b, err := dist.ReadFile("dist/index.html")
	if err != nil {
		return true
	}
	return strings.Contains(string(b), placeholderMarker)
}

// IndexHTML returns the embedded index.html bytes. Exposed for tests and for a
// potential future server-rendered shell; serving goes through Handler.
func IndexHTML() ([]byte, error) {
	return dist.ReadFile("dist/index.html")
}
