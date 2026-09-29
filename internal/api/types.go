// Package api serves the HTTP user/group directory that the nss_http NSS
// module (github.com/Eun/nss_http-go) queries on behalf of sshd.
//
// proxpass clients are not real Unix accounts. Instead sshd resolves them
// through NSS, which asks this API over loopback. That keeps user management
// entirely inside the proxpass database while letting OpenSSH handle the SSH
// protocol itself.
package api

// User is the passwd/shadow entry as expected by nss_http.
//
// The JSON field names are capitalized because that is the wire format
// nss_http unmarshals; see types/user.go in that repository. Do not
// "fix" these to lowercase, NSS lookups would silently return empty entries.
type User struct {
	User   string `json:"User"`
	Passwd string `json:"Passwd"`
	Name   string `json:"Name"`
	Dir    string `json:"Dir"`
	Shell  string `json:"Shell"`
	Uid    uint   `json:"Uid"` //nolint:revive // field name fixed by the nss_http wire format
	Gid    uint   `json:"Gid"` //nolint:revive // field name fixed by the nss_http wire format

	// AuthKeys is consumed by nss_http's sshkey helper. proxpass serves keys
	// through its own authorized-keys command instead, but the field is part
	// of the contract so it is populated anyway.
	AuthKeys []string `json:"AuthKeys"`
}

// Group is the group/gshadow entry as expected by nss_http.
type Group struct {
	Name         string   `json:"Name"`
	Passwd       string   `json:"Passwd"`
	Gid          uint     `json:"Gid"`
	GroupMembers []string `json:"GroupMembers"`
}
