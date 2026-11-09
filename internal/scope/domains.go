package scope

import (
	"errors"
	"net"
	"strings"
)

// normalizeAuthorizedDomain accepts a plain ASCII DNS name, not a URL,
// wildcard, IP address, or hostname with an invalid DNS label.
func normalizeAuthorizedDomain(value string) (string, error) {
	host := normHost(value)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /:*[]") {
		return "", errors.New("must be a plain DNS domain, not a URL, IP, or wildcard")
	}
	if net.ParseIP(host) != nil {
		return "", errors.New("IP addresses cannot be authorized as domains")
	}
	if !strings.Contains(host, ".") {
		return "", errors.New("an authorized domain must be a fully qualified DNS name")
	}

	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z') &&
				!(c >= '0' && c <= '9') && c != '-' {
				return "", errors.New("domain must use valid ASCII DNS labels (use punycode for international names)")
			}
		}
	}
	return host, nil
}

// domainMatches uses DNS-label boundaries: example.com matches
// example.com and api.example.com, but not notexample.com.
func domainMatches(host, domain string) bool {
	host = normHost(host)
	domain = normHost(domain)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// isPublicUnicast excludes private, loopback, link-local, unspecified,
// and multicast addresses from an explicitly authorized public-domain scope.
func isPublicUnicast(ip net.IP) bool {
	return ip != nil &&
		ip.IsGlobalUnicast() &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsUnspecified() &&
		!ip.IsMulticast()
}
