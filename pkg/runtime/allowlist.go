package runtime

import (
	"net"
	"net/url"
	"sort"
	"strings"
)

const wildcardPort = "*"

var defaultExternalDestinationPorts = []string{"22", "80", "443"}

type exactDestination struct {
	Host string
	Port string
}

func (d exactDestination) String() string {
	return d.Host + ":" + d.Port
}

type runtimeAllowlist struct {
	hosts        []string
	destinations []string
	portsByHost  map[string]map[string]struct{}
}

func buildRuntimeAllowlist(entries []string) runtimeAllowlist {
	hostSeen := map[string]struct{}{}
	destSeen := map[string]struct{}{}
	portsByHost := make(map[string]map[string]struct{})
	hosts := make([]string, 0, len(entries))
	destinations := make([]string, 0, len(entries)*2)

	for _, entry := range entries {
		for _, dest := range expandRuntimeDestinations(entry) {
			if _, ok := hostSeen[dest.Host]; !ok {
				hostSeen[dest.Host] = struct{}{}
				hosts = append(hosts, dest.Host)
			}
			if _, ok := portsByHost[dest.Host]; !ok {
				portsByHost[dest.Host] = make(map[string]struct{})
			}
			portsByHost[dest.Host][dest.Port] = struct{}{}
			key := dest.String()
			if _, ok := destSeen[key]; !ok {
				destSeen[key] = struct{}{}
				destinations = append(destinations, key)
			}
		}
	}

	sort.Strings(hosts)
	sort.Strings(destinations)
	return runtimeAllowlist{
		hosts:        hosts,
		destinations: destinations,
		portsByHost:  portsByHost,
	}
}

func (a runtimeAllowlist) Hosts() []string {
	return append([]string(nil), a.hosts...)
}

func (a runtimeAllowlist) Destinations() []string {
	return append([]string(nil), a.destinations...)
}

func (a runtimeAllowlist) Allows(host, port string) bool {
	if host == "" || port == "" {
		return false
	}
	// Fail closed on hosts that are not a clean ASCII hostname/IP. A NUL byte,
	// control character, whitespace, or non-ASCII rune is the shape of an
	// allowlist-bypass: the matcher and the OS resolver can disagree about where
	// the host ends (the Claude Code SOCKS5 `attacker.com\x00.allowed.com` class).
	// sir already uses exact matching rather than suffix matching, so a smuggled
	// host does not match an allowed entry — but rejecting it outright makes the
	// property explicit and refactor-proof on every proxy path.
	if !safeProxyHost(host) {
		return false
	}
	ports := a.portsByHost[host]
	if len(ports) == 0 {
		return false
	}
	if _, ok := ports[wildcardPort]; ok {
		return true
	}
	_, ok := ports[port]
	return ok
}

// safeProxyHost reports whether host is a clean ASCII hostname or IP literal
// safe to allowlist-match and dial. It rejects NUL bytes, control characters,
// whitespace, and non-ASCII runes — the characters that let a host smuggle a
// second name past a matcher (the resolver truncating at NUL / interpreting
// homoglyphs). Permitted: letters, digits, '.', '-', and IPv6 literal syntax
// (':', '%' zone id). Host is expected already lowercased and bracket-stripped
// by NormalizeProxyHost.
func safeProxyHost(host string) bool {
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == ':' || r == '%':
		default:
			return false
		}
	}
	return true
}

func expandRuntimeDestinations(raw string) []exactDestination {
	host, port, explicitPort := parseRuntimeDestination(raw)
	if host == "" {
		return nil
	}
	if explicitPort {
		return []exactDestination{{Host: host, Port: port}}
	}
	if isLoopbackRuntimeHost(host) {
		return []exactDestination{{Host: host, Port: wildcardPort}}
	}
	dests := make([]exactDestination, 0, len(defaultExternalDestinationPorts))
	for _, candidate := range defaultExternalDestinationPorts {
		dests = append(dests, exactDestination{Host: host, Port: candidate})
	}
	return dests
}

func parseRuntimeDestination(raw string) (host, port string, explicitPort bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}

	if strings.Contains(raw, "://") {
		if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
			host = NormalizeProxyHost(parsed.Hostname())
			if parsed.Port() != "" {
				return host, normalizePort(parsed.Port()), true
			}
			if defaultPort := schemeDefaultPort(parsed.Scheme); defaultPort != "" {
				return host, defaultPort, true
			}
			return host, "", false
		}
	}

	if parsed, err := url.Parse("//" + raw); err == nil && parsed.Host != "" {
		host = NormalizeProxyHost(parsed.Hostname())
		if parsed.Port() != "" {
			return host, normalizePort(parsed.Port()), true
		}
	}
	return NormalizeProxyHost(raw), "", false
}

func schemeDefaultPort(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		return "80"
	case "https":
		return "443"
	case "ssh":
		return "22"
	default:
		return ""
	}
}

func normalizePort(port string) string {
	port = strings.TrimSpace(port)
	if port == "" {
		return ""
	}
	return strings.TrimLeft(port, "+")
}

func isLoopbackRuntimeHost(host string) bool {
	host = NormalizeProxyHost(host)
	switch host {
	case "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
