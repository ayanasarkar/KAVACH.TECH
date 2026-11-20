package agent

import (
	"fmt"
	"net/url"
	"strings"
)

// normTarget canonicalises a step target so two spellings of the same endpoint compare equal:
// scheme and host are lower-cased, the default port (:80 for http, :443 for https) and a lone
// trailing "/" are dropped. Other ports, schemes, paths and queries stay distinct.
func normTarget(t string) string {
	t = strings.TrimSpace(t)
	if !strings.Contains(t, "://") {
		return strings.ToLower(t)
	}
	u, err := url.Parse(t)
	if err != nil || u.Host == "" {
		return strings.ToLower(t)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	out := scheme + "://" + host + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// redundantStep says why a proposed step would repeat work that is already finished, or "" if it is fine.
// The built-in portscan is only a fallback for when nmap is unavailable, so once nmap has completed on a
// host a portscan of that host adds nothing. Reads a.Steps only; caller holds a.mu.
func (a *Assessment) redundantStep(p proposal) string {
	if strings.ToLower(p.Tool) != "portscan" {
		return ""
	}
	host := strings.ToLower(hostOf(p.Target))
	if host == "" {
		return ""
	}
	for _, st := range a.Steps {
		if st.Tool == "nmap" && st.Status == "done" && strings.ToLower(hostOf(st.Target)) == host {
			return fmt.Sprintf("nmap (%s) already completed on %s and portscan is only a fallback for when nmap is unavailable", st.ID, host)
		}
	}
	return ""
}

// skipRedundant logs and audits a redundant proposal and reports whether it should be dropped. Caller holds a.mu.
func (a *Assessment) skipRedundant(p proposal, by string) bool {
	why := a.redundantStep(p)
	if why == "" {
		return false
	}
	a.event("info", fmt.Sprintf("Skipped redundant step %s on %s: %s.", p.Tool, p.Target, why))
	a.audit(by, "step_skipped", fmt.Sprintf("redundant %s on %s: %s", p.Tool, p.Target, why), nil)
	return true
}
