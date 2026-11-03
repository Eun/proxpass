package api

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// WriteNSSConfig renders the nss_http.json that libnss_http (the NSS module that
// resolves proxpass logins) reads, and writes it atomically to path.
//
// serve writes this file itself -- rather than a shell templating a checked-in
// file -- so the bearer token in it is the SAME value serve validates against,
// by construction. The old split (the entrypoint generated a token, sed'd it
// into a checked-in placeholder, and separately handed it to serve) could drift:
// a container recreate reset the checked-in file to its placeholder, and if the
// two sides ever disagreed, every NSS lookup was a 401 and nobody could log in.
// A single writer removes that whole failure class, and lets the entrypoint keep
// a plain random token with no templating.
//
// The URLs point at loopback on the listener's port: the NSS module runs in the
// same container as serve, so it reaches the directory over 127.0.0.1 regardless
// of which interface serve binds (listenAddr may be 0.0.0.0:8080).
//
// The write is atomic (temp file in the same directory + rename) so a login that
// reads the file never sees a half-written config, and the file is 0644 so the
// NSS module -- loaded into sshd and into every session -- can read it.
func WriteNSSConfig(path, listenAddr, nssToken string) error {
	host := "127.0.0.1"
	if _, port, err := net.SplitHostPort(listenAddr); err == nil && port != "" {
		host = net.JoinHostPort(host, port)
	}
	base := "http://" + host

	cfg := nssConfig{
		Providers: []nssProvider{{
			Name: "http",
			URLs: nssURLs{
				Users:     base + "/users",
				UserUID:   base + "/user/uid/",
				UserName:  base + "/user/name/",
				Groups:    base + "/groups",
				GroupGID:  base + "/group/gid/",
				GroupName: base + "/group/name/",
			},
			RequestTimeout: "5s",
			Headers: map[string]string{
				"Authorization": "Bearer " + nssToken,
			},
		}},
		Cache:                nssCache{Name: "disabled"},
		AllowListingOfUsers:  false,
		AllowListingOfGroups: false,
		DisableShadow:        false,
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling nss config: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".nss_http.*.json")
	if err != nil {
		return fmt.Errorf("creating temp nss config in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp nss config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp nss config: %w", err)
	}
	// 0644: readable by the NSS module in sshd and in every session. It holds
	// the bearer token, but that token only grants read access to the directory
	// those same processes resolve through anyway.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod temp nss config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("installing nss config at %s: %w", path, err)
	}
	return nil
}

// The nss_http.json shape that github.com/Eun/nss_http-go reads. Only the fields
// proxpass sets are modeled; see docker/nss_http.json for the full reference.
type nssConfig struct {
	Providers            []nssProvider `json:"Providers"`
	Cache                nssCache      `json:"Cache"`
	AllowListingOfUsers  bool          `json:"AllowListingOfUsers"`
	AllowListingOfGroups bool          `json:"AllowListingOfGroups"`
	DisableShadow        bool          `json:"DisableShadow"`
}

type nssProvider struct {
	Name           string            `json:"Name"`
	URLs           nssURLs           `json:"URLs"`
	RequestTimeout string            `json:"RequestTimeout"`
	Headers        map[string]string `json:"Headers"`
}

type nssURLs struct {
	Users     string `json:"Users"`
	UserUID   string `json:"UserUID"`
	UserName  string `json:"UserName"`
	Groups    string `json:"Groups"`
	GroupGID  string `json:"GroupGID"`
	GroupName string `json:"GroupName"`
}

type nssCache struct {
	Name string `json:"Name"`
}
