// Package adapters wraps security tools behind one interface. Each adapter is
// honest about its mode: live, import-only, or approval-gated.
package adapters

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// Mode is the truthful integration mode shown in the integration matrix.
type Mode string

const (
	Live      Mode = "live"
	ImportOnl Mode = "import-only"
	Gated     Mode = "live (approval-gated)"
)

// Job is one invocation.
type Job struct {
	Target     string            // host, host:port or URL
	Host       string            // resolved host part
	Port       int               // 0 if unspecified
	Options    map[string]string // adapter specific
	ImportPath string            // for import adapters
	AllowPort  func(int) bool    // scope port allow-list
	Limiter    *scope.Limiter

	AllowedPorts []int                              // the scope's port list (empty = any); restricts default sweeps
	MaxReqPerSec int                                // scope rate limit, passed to tools that have a native rate option
	DialCheck    func(host string, ip net.IP) error // connect-time scope check (DNS-rebinding defence)
}

// dialer returns a net.Dialer that re-validates every resolved address at connect time, so a hostname
// that was in scope when planned cannot be rebound to another address before the connection is made.
func (j Job) dialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if j.DialCheck != nil {
		host := j.Host
		d.Control = func(network, address string, _ syscall.RawConn) error {
			h, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(h)
			if ip == nil {
				return fmt.Errorf("unparseable dial address %q", address)
			}
			return j.DialCheck(host, ip)
		}
	}
	return d
}

// Result is the raw outcome of a tool run.
type Result struct {
	Services []model.Service
	Findings []model.RawFinding
	Raw      string // full raw output retained for evidence
	Summary  string
	// Validation is set only by approval-gated validation adapters.
	Validation *Validation
}

// Validation is the outcome of a human-approved, lab-only validation check.
type Validation struct {
	Verdict string // vulnerable | not_vulnerable | undetermined
	Module  string
	Line    string // verbatim tool output line supporting the verdict
}

// Adapter is implemented by every tool.
type Adapter interface {
	Name() string
	Mode() Mode
	Kind() scope.Kind
	Describe() string
	// Available reports whether the tool can run now; reason explains if not.
	Available() (bool, string)
	Run(ctx context.Context, j Job) (Result, error)
}

// Registry holds adapters by name.
type Registry struct{ m map[string]Adapter }

// NewRegistry builds the default registry.
func NewRegistry() *Registry {
	r := &Registry{m: map[string]Adapter{}}
	for _, a := range []Adapter{
		&PortScan{}, &WebCheck{}, &Nmap{}, &Nikto{}, &ZAP{},
		&Nessus{}, &OpenVAS{}, &Burp{}, &Metasploit{},
	} {
		r.m[a.Name()] = a
	}
	return r
}

// Get returns an adapter.
func (r *Registry) Get(n string) (Adapter, bool) { a, ok := r.m[strings.ToLower(n)]; return a, ok }

// All returns adapters sorted by name.
func (r *Registry) All() []Adapter {
	var out []Adapter
	for _, a := range r.m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

var cveRe = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

// FindCVEs extracts distinct CVE ids verbatim from text.
func FindCVEs(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range cveRe.FindAllString(s, -1) {
		m = strings.ToUpper(m)
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

var cweRe = regexp.MustCompile(`(?i)CWE[-:\s]*(\d{1,5})`)

// FindCWEs extracts CWE ids.
func FindCWEs(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range cweRe.FindAllStringSubmatch(s, -1) {
		id := "CWE-" + m[1]
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func fptr(f float64) *float64 { return &f }
func bptr(b bool) *bool       { return &b }

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + " …[truncated]"
}

// NormalizeKey maps tool-specific titles to a shared vulnerability identity so
// the same weakness found by different tools is correlated (not duplicated).
func NormalizeKey(title, extra string) string {
	t := strings.ToLower(title + " " + extra)
	has := func(ss ...string) bool {
		for _, s := range ss {
			if strings.Contains(t, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("x-frame-options", "clickjack", "frame-ancestors"):
		return "web:missing-header:x-frame-options"
	case has("x-content-type-options"):
		return "web:missing-header:x-content-type-options"
	case has("content security policy", "content-security-policy", "csp header"):
		return "web:missing-header:content-security-policy"
	case has("strict-transport-security", "hsts"):
		return "web:missing-header:hsts"
	case has("directory browsing", "directory indexing", "directory listing", "index of /"):
		return "web:directory-listing"
	case has("x-powered-by"):
		return "web:version-disclosure:x-powered-by"
	case has("server leaks", "server banner", "server header", "web server may reveal", "version disclosure", "server version"):
		return "web:version-disclosure:server"
	case has("httponly"):
		return "web:cookie-httponly"
	case has("cookie") && has("secure flag", "without the secure", "secure attribute"):
		return "web:cookie-secure"
	case has(".git/", ".git repository", "git metadata"):
		return "web:exposed-git"
	case has(".env", "environment file"):
		return "web:exposed-env"
	case has("server-status"):
		return "web:server-status"
	case has("phpinfo"):
		return "web:phpinfo"
	case has("cleartext", "unencrypted", "plain text", "plaintext") && has("login", "password", "credential", "form"):
		return "web:cleartext-credentials"
	case has("telnet"):
		return "net:cleartext:telnet"
	case has("ftp") && has("cleartext", "unencrypted", "anonymous", "plain"):
		return "net:cleartext:ftp"
	}
	return ""
}
