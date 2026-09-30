package api

// MaxLoginNameLen bounds a login name. NSS and sshd both cope with longer
// ones, but a login this long is a mistake rather than an intent.
const MaxLoginNameLen = 32

// ValidLoginName reports whether name is safe to serve as a Unix login name.
//
// The rules are deliberately conservative: start with a letter or underscore,
// then letters, digits, underscore or hyphen. That keeps the name safe in
// /etc/passwd-style output, in a URL path segment (the directory API builds
// its routes by concatenation and does not escape them), and in the shell
// wrappers sshd invokes.
//
// It gates two things: which client names may be created, and which unknown
// names the directory is willing to serve as an administrator alias.
func ValidLoginName(name string) bool {
	if name == "" || len(name) > MaxLoginNameLen {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case i > 0 && (r >= '0' && r <= '9' || r == '-'):
		default:
			return false
		}
	}
	return true
}
