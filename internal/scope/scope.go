// Package scope implements the deny-by-default authorization guard.
// Every tool invocation proposed by the planner (LLM or rules) must pass
// Guard.Check before it is executed. The guard never trusts model output.
package scope

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kind classifies how intrusive an action is.
type Kind string

const (
	KindPassive Kind = "passive" // read-only, no payloads (imports, banner grabs, HEAD/GET)
	KindActive  Kind = "active"  // sends probes/scans (nmap, nikto, zap)
	KindExploit Kind = "exploit" // offensive validation: ALWAYS needs human approval
)

// Scope is the authorization record registered by the analyst.
type Scope struct {
	Name              string    `json:"name"`
	Authorization     string    `json:"authorization"`      // ticket / organiser reference
	Targets           []string  `json:"targets"`            // CIDR, IP or hostname
	AuthorizedDomains []string  `json:"authorized_domains"` // explicitly approved DNS domain trees
	Exclusions        []string  `json:"exclusions"`         // CIDR, IP or hostname
	Ports             []int     `json:"ports"`              // optional allow-list; empty = any
	AllowedTools      []string  `json:"allowed_tools"`      // empty = all registered tools
	AllowActive       bool      `json:"allow_active"`       // permits KindActive scans
	AllowExploit      bool      `json:"allow_exploit"`      // permits proposing KindExploit (still gated)
	AllowNonLab       bool      `json:"allow_non_lab"`      // organiser override: permit non-private addresses
	MaxReqPerSec      int       `json:"max_req_per_sec"`
	Expires           time.Time `json:"expires"`
}

// Action is a single proposed tool run.
type Action struct {
	Tool   string
	Target string // host, host:port or URL
	Kind   Kind
}

// Decision is the guard's verdict.
type Decision struct {
	Allowed       bool   `json:"allowed"`
	NeedsApproval bool   `json:"needs_approval"`
	Reason        string `json:"reason"`
}

// Guard enforces a Scope.
type Guard struct {
	mu                sync.Mutex
	sc                Scope
	targets           []matcher
	authorizedDomains []string
	excl              []matcher
	lookup            func(string) ([]net.IP, error)
	now               func() time.Time
	exclIPs           map[string]exclEntry // resolved addresses of hostname exclusions (short TTL cache)
}

type exclEntry struct {
	ips []net.IP
	at  time.Time
}

type matcher struct {
	raw  string
	cidr *net.IPNet
	ip   net.IP
	host string
}

// New validates the scope itself and returns a guard.
func New(sc Scope) (*Guard, error) {
	g := &Guard{sc: sc, lookup: net.LookupIP, now: time.Now, exclIPs: map[string]exclEntry{}}
	if len(sc.Targets) == 0 {
		return nil, errors.New("scope has no targets")
	}
	if strings.TrimSpace(sc.Authorization) == "" {
		return nil, errors.New("scope needs an authorization reference (organiser ticket / rules-of-engagement id)")
	}
	// Authorized domains are validated and stored before targets are processed, because a
	// target's lab-only requirement below is waived only for a hostname that matches one of them.
	for _, d := range sc.AuthorizedDomains {
		nd, err := normalizeAuthorizedDomain(d)
		if err != nil {
			return nil, fmt.Errorf("authorized domain %q: %w", d, err)
		}
		g.authorizedDomains = append(g.authorizedDomains, nd)
	}
	for _, t := range sc.Targets {
		m, err := parseMatcher(t)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", t, err)
		}
		if !sc.AllowNonLab && !(m.host != "" && g.authorizedDomain(m.host)) {
			if err := labOnly(m); err != nil {
				return nil, fmt.Errorf("target %q: %w", t, err)
			}
		}
		g.targets = append(g.targets, m)
	}
	for _, e := range sc.Exclusions {
		m, err := parseMatcher(e)
		if err != nil {
			return nil, fmt.Errorf("exclusion %q: %w", e, err)
		}
		g.excl = append(g.excl, m)
	}
	return g, nil
}

// Scope returns a copy of the registered scope.
func (g *Guard) Scope() Scope { return g.sc }

// authorizedDomain reports whether host falls under one of the scope's explicitly
// organiser-authorized DNS domain trees (named domains only — never an IP literal
// or CIDR, and this list is only ever populated from the scope the analyst registered).
func (g *Guard) authorizedDomain(host string) bool {
	for _, d := range g.authorizedDomains {
		if domainMatches(host, d) {
			return true
		}
	}
	return false
}

// SetLookup replaces the resolver (tests).
func (g *Guard) SetLookup(f func(string) ([]net.IP, error)) {
	g.mu.Lock()
	g.lookup = f
	g.exclIPs = map[string]exclEntry{}
	g.mu.Unlock()
}

// excluded reports whether the host (given by name and/or resolved addresses) is an excluded machine.
// A hostname exclusion also excludes every address that name resolves to, so the same box cannot be
// reached by IP or by an alias.
func (g *Guard) excluded(host string, ips []net.IP, lookup func(string) ([]net.IP, error)) (string, bool) {
	cand := ips
	if ip := net.ParseIP(host); ip != nil {
		cand = []net.IP{ip}
	}
	for _, e := range g.excl {
		if e.contains(host, ips) {
			return e.raw, true
		}
		if e.host == "" {
			continue
		}
		for _, x := range g.exclAddrs(e.host, lookup) {
			for _, c := range cand {
				if x.Equal(c) {
					return e.raw, true
				}
			}
		}
	}
	return "", false
}

func (g *Guard) exclAddrs(name string, lookup func(string) ([]net.IP, error)) []net.IP {
	g.mu.Lock()
	if c, ok := g.exclIPs[name]; ok && g.now().Sub(c.at) < 30*time.Second {
		g.mu.Unlock()
		return c.ips
	}
	g.mu.Unlock()
	ips, _ := lookup(name) // outside the lock
	g.mu.Lock()
	g.exclIPs[name] = exclEntry{ips: ips, at: g.now()}
	g.mu.Unlock()
	return ips
}

// CheckDial is the connect-time check. It is called by the built-in checkers for every address a
// connection is about to be made to, after DNS, so a name that was in scope when planned cannot be
// rebound to an out-of-scope or non-lab address between the guard check and the connection.
func (g *Guard) CheckDial(host string, ip net.IP) error {
	host = normHost(host)
	g.mu.Lock()
	lookup := g.lookup
	g.mu.Unlock()
	if name, bad := g.excluded(host, []net.IP{ip}, lookup); bad {
		return fmt.Errorf("%s resolves to %s which matches exclusion %q", host, ip, name)
	}
	if g.authorizedDomain(host) {
		if !isPublicUnicast(ip) {
			return fmt.Errorf("%s resolves to %s, which is not a public address — refusing an authorized-domain connection (possible DNS rebinding)", host, ip)
		}
	} else if !g.sc.AllowNonLab && !isLab(ip) {
		return fmt.Errorf("%s resolves to non-lab address %s at connect time", host, ip)
	}
	for _, t := range g.targets {
		if (t.host != "" && t.host == host) || (t.ip != nil && t.ip.Equal(ip)) || (t.cidr != nil && t.cidr.Contains(ip)) {
			return nil
		}
	}
	return fmt.Errorf("%s resolved to %s, which is outside the authorised scope at connect time", host, ip)
}

func parseMatcher(s string) (matcher, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return matcher{}, errors.New("empty entry")
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return matcher{raw: s, cidr: n}, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return matcher{raw: s, ip: ip}, nil
	}
	if strings.ContainsAny(s, " /*") {
		return matcher{}, errors.New("not a CIDR, IP or plain hostname (wildcards are not allowed)")
	}
	return matcher{raw: s, host: normHost(s)}, nil
}

// normHost lower-cases and strips the root-label dot, so "ADMIN.lab." and "admin.lab" are one name.
func normHost(h string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".") }

func isLab(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func labOnly(m matcher) error {
	switch {
	case m.ip != nil:
		if !isLab(m.ip) {
			return errors.New("public address: lab-only mode requires loopback/private ranges (set allow_non_lab only when the organiser authorised it)")
		}
	case m.cidr != nil:
		if !isLab(m.cidr.IP) {
			return errors.New("public CIDR: lab-only mode requires loopback/private ranges")
		}
		if ones, bits := m.cidr.Mask.Size(); bits-ones > 16 {
			return errors.New("CIDR too large for a lab assessment (max /16 for IPv4)")
		}
	}
	return nil
}

func (m matcher) contains(host string, ips []net.IP) bool {
	switch {
	case m.host != "":
		return normHost(host) == m.host
	case m.ip != nil:
		if p := net.ParseIP(host); p != nil && p.Equal(m.ip) {
			return true
		}
		for _, ip := range ips {
			if ip.Equal(m.ip) {
				return true
			}
		}
	case m.cidr != nil:
		if p := net.ParseIP(host); p != nil && m.cidr.Contains(p) {
			return true
		}
		for _, ip := range ips {
			if m.cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// SplitTarget extracts host and port (0 if absent) from host, host:port or URL.
func SplitTarget(t string) (host string, port int, err error) {
	t = strings.TrimSpace(t)
	if t == "" {
		return "", 0, errors.New("empty target")
	}
	if strings.Contains(t, "://") {
		u, e := url.Parse(t)
		if e != nil || u.Hostname() == "" {
			return "", 0, fmt.Errorf("bad URL %q", t)
		}
		host = u.Hostname()
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		} else if u.Scheme == "https" {
			port = 443
		} else if u.Scheme == "http" {
			port = 80
		}
		return host, port, nil
	}
	if h, p, e := net.SplitHostPort(t); e == nil {
		port, _ = strconv.Atoi(p)
		return h, port, nil
	}
	return strings.Trim(t, "[]"), 0, nil
}

// Check decides whether an action may run. Default is deny.
func (g *Guard) Check(a Action) Decision {
	g.mu.Lock()
	lookup, now := g.lookup, g.now
	g.mu.Unlock() // never hold the lock across DNS: one slow lookup must not stall every other check
	deny := func(f string, args ...any) Decision {
		return Decision{Allowed: false, Reason: fmt.Sprintf(f, args...)}
	}
	if !g.sc.Expires.IsZero() && now().After(g.sc.Expires) {
		return deny("authorization window expired at %s", g.sc.Expires.Format(time.RFC3339))
	}
	host, port, err := SplitTarget(a.Target)
	if err != nil {
		return deny("%v", err)
	}
	host = normHost(host)
	var ips []net.IP
	if net.ParseIP(host) == nil {
		ips, err = lookup(host)
		if err != nil || len(ips) == 0 {
			// Hostnames that don't resolve can still match a hostname entry exactly.
			ips = nil
		}
	}
	if name, bad := g.excluded(host, ips, lookup); bad {
		return deny("%s matches exclusion %q", host, name)
	}
	in := false
	for _, t := range g.targets {
		if t.contains(host, ips) {
			in = true
			break
		}
	}
	if !in {
		return deny("%s is outside the authorised scope", host)
	}
	// Every resolved address must itself be lab-safe, UNLESS the organiser gave a blanket
	// non-lab override, or the host falls under an explicitly authorized domain — in which
	// case it must instead resolve to a genuine public address (never private/loopback,
	// which would indicate DNS rebinding rather than a real reachable site).
	authDomain := g.authorizedDomain(host)
	cand := ips
	if ip := net.ParseIP(host); ip != nil {
		cand = []net.IP{ip}
	}
	switch {
	case authDomain:
		if len(cand) == 0 {
			return deny("%s could not be resolved, so the authorized-domain address cannot be verified (fail closed)", host)
		}
		for _, ip := range cand {
			if !isPublicUnicast(ip) {
				return deny("%s resolves to %s, which is not a public address — refusing an authorized-domain target (possible DNS rebinding)", host, ip)
			}
		}
	case !g.sc.AllowNonLab:
		if len(cand) == 0 {
			return deny("%s could not be resolved, so lab-only addressing cannot be verified (fail closed)", host)
		}
		for _, ip := range cand {
			if !isLab(ip) {
				return deny("%s resolves to non-lab address %s", host, ip)
			}
		}
	}
	if len(g.sc.Ports) > 0 && port != 0 {
		ok := false
		for _, p := range g.sc.Ports {
			if p == port {
				ok = true
			}
		}
		if !ok {
			return deny("port %d is not in the authorised port list", port)
		}
	}
	// "request" and "probe" are membership checks, not tool runs: the tool allow-list
	// applies only to real tool executions.
	if len(g.sc.AllowedTools) > 0 && a.Tool != "request" && a.Tool != "probe" {
		ok := false
		for _, t := range g.sc.AllowedTools {
			if strings.EqualFold(t, a.Tool) {
				ok = true
			}
		}
		if !ok {
			return deny("tool %q is not permitted by this scope", a.Tool)
		}
	}
	switch a.Kind {
	case KindPassive:
		return Decision{Allowed: true, Reason: "in scope, passive"}
	case KindActive:
		if !g.sc.AllowActive {
			return deny("active scanning is not enabled in this scope")
		}
		return Decision{Allowed: true, Reason: "in scope, active scan permitted"}
	case KindExploit:
		if !g.sc.AllowExploit {
			return deny("offensive validation is not enabled in this scope")
		}
		return Decision{Allowed: true, NeedsApproval: true, Reason: "in scope; offensive validation requires explicit human approval"}
	}
	return deny("unknown action kind %q", a.Kind)
}

// Limiter is a simple per-assessment request limiter honouring MaxReqPerSec.
type Limiter struct {
	mu   sync.Mutex
	gap  time.Duration
	next time.Time
}

// NewLimiter returns a limiter; rate<=0 means unlimited.
func NewLimiter(rate int) *Limiter {
	l := &Limiter{}
	if rate > 0 {
		l.gap = time.Second / time.Duration(rate)
	}
	return l
}

// Wait blocks until the next request slot.
func (l *Limiter) Wait() {
	if l == nil || l.gap == 0 {
		return
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.gap)
	l.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}
