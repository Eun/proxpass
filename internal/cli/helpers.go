package cli

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// parseHostPort splits a "host" or "host:port" string. If no port
// is present, defaultPort is used.
func parseHostPort(hostport string, defaultPort int) (host string, port int, err error) {
	var portStr string
	host, portStr, err = net.SplitHostPort(hostport)
	if err != nil {
		// No port — treat the whole string as host.
		return hostport, defaultPort, nil
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q", portStr)
	}
	return host, port, nil
}

// validateAPIURL checks that rawURL is a valid Proxmox API URL with an
// explicit port. It rejects:
//   - Missing scheme (e.g. "pve:8006" — url.Parse treats "pve" as the scheme
//     and silently drops the port)
//   - Non-http/https schemes
//   - Missing host
//   - Missing port (requests would go to the scheme default, 80 or 443)
func validateAPIURL(rawURL string) error {
	trimmed := strings.TrimRight(rawURL, "/")
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("--api-url %q: %w", rawURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("--api-url %q: must start with http:// or https://", rawURL)
	}
	if parsed.Host == "" {
		return fmt.Errorf("--api-url %q: missing host", rawURL)
	}
	if parsed.Port() == "" {
		return fmt.Errorf("--api-url %q: port is required (e.g. https://%s:8006)", rawURL, parsed.Hostname())
	}
	return nil
}
