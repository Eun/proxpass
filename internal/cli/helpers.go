package cli

import (
	"fmt"
	"net"
	"strconv"
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
