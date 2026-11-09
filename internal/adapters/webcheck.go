package adapters

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// WebCheck is a built-in, read-only HTTP configuration checker. It only issues
// GET requests, never follows redirects off the target, and verifies content
// (not just status codes) to avoid soft-404 false positives.
type WebCheck struct{}

func (*WebCheck) Name() string     { return "webcheck" }
func (*WebCheck) Mode() Mode       { return Live }
func (*WebCheck) Kind() scope.Kind { return scope.KindPassive }
func (*WebCheck) Describe() string {
	return "Built-in read-only HTTP checks: security headers, cookies, banners, directory listing, exposed sensitive files (content-verified)."
}
func (*WebCheck) Available() (bool, string) { return true, "" }

type httpResp struct {
	status int
	hdr    http.Header
	body   string
	url    string
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (w *WebCheck) get(ctx context.Context, cl *http.Client, lim *scope.Limiter, u string) (httpResp, error) {
	lim.Wait()
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("User-Agent", "vapt-agent/0.1 (authorized lab assessment)")
	resp, err := cl.Do(req)
	if err != nil {
		return httpResp{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return httpResp{status: resp.StatusCode, hdr: resp.Header, body: string(b), url: u}, nil
}

func (w *WebCheck) Run(ctx context.Context, j Job) (Result, error) {
	base := j.Target
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	bu, err := url.Parse(base)
	if err != nil {
		return Result{}, err
	}
	cl := &http.Client{Timeout: 6 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: j.dialer(6 * time.Second).DialContext}, // lab self-signed certs; we only read
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	root, err := w.get(ctx, cl, j.Limiter, base)
	if err != nil {
		return Result{}, fmt.Errorf("GET %s: %w", base, err)
	}
	host := bu.Hostname()
	port := 80
	if bu.Scheme == "https" {
		port = 443
	}
	if p := bu.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	var raw strings.Builder
	line := 0
	emit := func(s string) int { fmt.Fprintln(&raw, s); line++; return line }
	emit(fmt.Sprintf("# webcheck %s %s", base, time.Now().UTC().Format(time.RFC3339)))
	emit(fmt.Sprintf("GET %s -> %d", base, root.status))
	hdrLine := map[string]int{}
	for k, v := range root.hdr {
		hdrLine[strings.ToLower(k)] = emit(fmt.Sprintf("%s: %s", k, strings.Join(v, "; ")))
	}
	res := Result{}
	add := func(rf model.RawFinding) {
		rf.Tool, rf.Host, rf.Port, rf.Proto, rf.Basis = "webcheck", host, port, "tcp", model.BasisDirect
		res.Findings = append(res.Findings, rf)
	}
	title := ""
	if m := titleRe.FindStringSubmatch(root.body); m != nil {
		title = strings.TrimSpace(m[1])
	}
	emit(fmt.Sprintf("page title: %q, body bytes: %d", title, len(root.body)))
	svc := model.Service{Host: host, Port: port, Proto: "tcp", State: "open", Name: bu.Scheme, Tool: "webcheck", Product: root.hdr.Get("Server"), Banner: fmt.Sprintf("HTTP %d title=%q", root.status, title)}
	res.Services = append(res.Services, svc)

	type hdrCheck struct {
		h, key, title, desc, fix string
		cwe                      []string
		sev                      string
		httpsOnly                bool
	}
	for _, c := range []hdrCheck{
		{"content-security-policy", "web:missing-header:content-security-policy", "Missing Content-Security-Policy header",
			"The response has no Content-Security-Policy, which weakens defence-in-depth against cross-site scripting and content injection.",
			"Define a restrictive Content-Security-Policy (default-src 'self') and tighten it iteratively.", []string{"CWE-693"}, "low", false},
		{"x-frame-options", "web:missing-header:x-frame-options", "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
			"Neither X-Frame-Options nor a CSP frame-ancestors directive is present, so the page can be framed by other origins.",
			"Send 'X-Frame-Options: DENY' (or SAMEORIGIN) or a CSP 'frame-ancestors' directive.", []string{"CWE-1021"}, "low", false},
		{"x-content-type-options", "web:missing-header:x-content-type-options", "Missing X-Content-Type-Options header",
			"Responses lack 'X-Content-Type-Options: nosniff', allowing MIME sniffing in some browsers.",
			"Send 'X-Content-Type-Options: nosniff' on all responses.", []string{"CWE-693"}, "low", false},
		{"strict-transport-security", "web:missing-header:hsts", "Missing HTTP Strict-Transport-Security header",
			"An HTTPS response lacks HSTS, so browsers may be downgraded to HTTP.",
			"Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.", []string{"CWE-319"}, "low", true},
	} {
		if c.httpsOnly && bu.Scheme != "https" {
			continue
		}
		if c.key == "web:missing-header:x-frame-options" && strings.Contains(strings.ToLower(root.hdr.Get("Content-Security-Policy")), "frame-ancestors") {
			continue
		}
		if root.hdr.Get(c.h) == "" {
			ref := emit(fmt.Sprintf("CHECK absent header %s", c.h))
			add(model.RawFinding{Key: c.key, Title: c.title, Description: c.desc, Severity: c.sev, CWEs: c.cwe, Remediation: c.fix,
				OWASP: "A05:2021 Security Misconfiguration", Excerpt: fmt.Sprintf("GET %s -> %d; response headers contain no %q header", base, root.status, c.h),
				RawRef: fmt.Sprintf("line %d", ref), References: []string{"https://owasp.org/www-project-secure-headers/"}})
		}
	}
	if sv := root.hdr.Get("Server"); sv != "" && strings.ContainsAny(sv, "0123456789/") {
		add(model.RawFinding{Key: "web:version-disclosure:server", Title: "Web server discloses software/version in Server header", Severity: "info",
			CWEs: []string{"CWE-200"}, OWASP: "A05:2021 Security Misconfiguration",
			Description: "The Server header reveals product and version, helping attackers choose targeted exploits.",
			Remediation: "Remove or genericise the Server header (e.g. ServerTokens Prod / server_tokens off).",
			Excerpt:     "Server: " + sv, RawRef: fmt.Sprintf("line %d", hdrLine["server"])})
	}
	if xp := root.hdr.Get("X-Powered-By"); xp != "" {
		add(model.RawFinding{Key: "web:version-disclosure:x-powered-by", Title: "X-Powered-By header discloses technology stack", Severity: "info",
			CWEs: []string{"CWE-200"}, OWASP: "A05:2021 Security Misconfiguration",
			Description: "The X-Powered-By header reveals the application framework or runtime.",
			Remediation: "Disable the X-Powered-By header in the framework or reverse proxy.",
			Excerpt:     "X-Powered-By: " + xp, RawRef: fmt.Sprintf("line %d", hdrLine["x-powered-by"])})
	}
	for _, ck := range root.hdr.Values("Set-Cookie") {
		lc := strings.ToLower(ck)
		name, _, _ := strings.Cut(ck, "=")
		ref := emit("Set-Cookie: " + redactCookie(ck))
		if !strings.Contains(lc, "httponly") {
			add(model.RawFinding{Key: "web:cookie-httponly", Title: "Cookie set without HttpOnly flag", Severity: "low", CWEs: []string{"CWE-1004"},
				OWASP:       "A05:2021 Security Misconfiguration",
				Description: "A cookie is issued without HttpOnly, so client-side script can read it if XSS exists.",
				Remediation: "Set HttpOnly on session and authentication cookies.", Excerpt: "Set-Cookie: " + redactCookie(ck), RawRef: fmt.Sprintf("line %d (cookie %s)", ref, name)})
		}
		if bu.Scheme == "https" && !strings.Contains(lc, "secure") {
			add(model.RawFinding{Key: "web:cookie-secure", Title: "Cookie set without Secure flag over HTTPS", Severity: "low", CWEs: []string{"CWE-614"},
				OWASP:       "A05:2021 Security Misconfiguration",
				Description: "A cookie issued over HTTPS lacks the Secure attribute and may be sent over plain HTTP.",
				Remediation: "Set the Secure attribute on all cookies served over HTTPS.", Excerpt: "Set-Cookie: " + redactCookie(ck), RawRef: fmt.Sprintf("line %d (cookie %s)", ref, name)})
		}
	}
	lb := strings.ToLower(root.body)
	if bu.Scheme == "http" && strings.Contains(lb, `type="password"`) || bu.Scheme == "http" && strings.Contains(lb, `type='password'`) {
		ref := emit("CHECK password input served over plain HTTP")
		add(model.RawFinding{Key: "web:cleartext-credentials", Title: "Login form served over unencrypted HTTP", Severity: "high", CWEs: []string{"CWE-319"},
			OWASP:       "A02:2021 Cryptographic Failures",
			Description: "A page containing a password field is delivered over plain HTTP, so credentials can be intercepted on the network.",
			Remediation: "Serve all authenticated pages over HTTPS and redirect HTTP to HTTPS.", Excerpt: fmt.Sprintf("GET %s -> %d; HTML contains an input of type=password", base, root.status), RawRef: fmt.Sprintf("line %d", ref)})
	}
	if strings.Contains(root.body, "Index of /") || strings.Contains(lb, "<title>index of") {
		ref := emit("CHECK directory listing on /")
		add(model.RawFinding{Key: "web:directory-listing", Title: "Directory listing enabled", Severity: "medium", CWEs: []string{"CWE-548"},
			OWASP:       "A05:2021 Security Misconfiguration",
			Description: "The web server returns an auto-generated directory index, exposing file names and structure.",
			Remediation: "Disable directory indexing (Options -Indexes / autoindex off) and place an index document in each directory.",
			Excerpt:     clip(titleOrBody(root.body), 200), RawRef: fmt.Sprintf("line %d", ref)})
	}
	// Soft-404 baseline: a random path tells us how this site answers "not found".
	rb := make([]byte, 8)
	rand.Read(rb)
	baseline, berr := w.get(ctx, cl, j.Limiter, strings.TrimRight(base, "/")+"/"+hex.EncodeToString(rb))
	soft := berr == nil && baseline.status == 200
	baseHash := ""
	if berr == nil {
		s := sha256.Sum256([]byte(baseline.body))
		baseHash = hex.EncodeToString(s[:4])
		emit(fmt.Sprintf("baseline random path -> %d (soft-404=%v)", baseline.status, soft))
	}
	type pathCheck struct {
		path, key, title, sev, desc, fix string
		cwe                              []string
		verify                           func(httpResp) (string, bool)
	}
	checks := []pathCheck{
		{"/.git/HEAD", "web:exposed-git", "Exposed .git repository metadata", "high", "The /.git/ directory is reachable; source code and secrets may be reconstructable.",
			"Block access to /.git/ at the web server and remove VCS metadata from deployed content.", []string{"CWE-527"},
			func(r httpResp) (string, bool) {
				return firstLine(r.body), strings.HasPrefix(strings.TrimSpace(r.body), "ref:")
			}},
		{"/.env", "web:exposed-env", "Exposed environment file (.env)", "high", "An environment file is downloadable and typically holds credentials and API keys.",
			"Remove .env from the web root and rotate every secret it contained.", []string{"CWE-538"},
			func(r httpResp) (string, bool) {
				ks := envKeys(r.body)
				return "keys present (values redacted): " + strings.Join(ks, ", "), len(ks) >= 1 && !strings.Contains(strings.ToLower(r.body), "<html")
			}},
		{"/server-status", "web:server-status", "Apache server-status page exposed", "medium", "mod_status output is reachable and reveals requests, clients and workers.",
			"Restrict /server-status to localhost or remove mod_status.", []string{"CWE-200"},
			func(r httpResp) (string, bool) {
				return clip(titleOrBody(r.body), 120), strings.Contains(r.body, "Apache Server Status")
			}},
		{"/phpinfo.php", "web:phpinfo", "phpinfo() page exposed", "medium", "phpinfo output discloses configuration, paths and environment.",
			"Delete phpinfo pages from production hosts.", []string{"CWE-200"},
			func(r httpResp) (string, bool) {
				return clip(titleOrBody(r.body), 120), strings.Contains(r.body, "PHP Version")
			}},
	}
	for _, c := range checks {
		r, err := w.get(ctx, cl, j.Limiter, strings.TrimRight(base, "/")+c.path)
		if err != nil {
			emit(fmt.Sprintf("GET %s -> error %v", c.path, err))
			continue
		}
		ref := emit(fmt.Sprintf("GET %s -> %d", c.path, r.status))
		if r.status != 200 {
			continue
		}
		s := sha256.Sum256([]byte(r.body))
		if soft && hex.EncodeToString(s[:4]) == baseHash {
			emit(fmt.Sprintf("  %s identical to soft-404 baseline: ignored", c.path))
			continue
		}
		ex, ok := c.verify(r)
		if !ok {
			emit(fmt.Sprintf("  %s returned 200 but content did not match expected signature: ignored", c.path))
			continue
		}
		add(model.RawFinding{Key: c.key, Title: c.title, Severity: c.sev, CWEs: c.cwe, OWASP: "A05:2021 Security Misconfiguration",
			Description: c.desc, Remediation: c.fix, Excerpt: fmt.Sprintf("GET %s -> 200; %s", c.path, ex), RawRef: fmt.Sprintf("line %d", ref)})
	}
	res.Raw = raw.String()
	res.Summary = fmt.Sprintf("%s -> HTTP %d, %d issues", base, root.status, len(res.Findings))
	return res, nil
}

func redactCookie(c string) string {
	name, rest, ok := strings.Cut(c, "=")
	if !ok {
		return c
	}
	_, attrs, _ := strings.Cut(rest, ";")
	return name + "=<redacted>;" + attrs
}
func titleOrBody(b string) string {
	if m := titleRe.FindStringSubmatch(b); m != nil {
		return strings.TrimSpace(m[1])
	}
	return strings.Join(strings.Fields(b), " ")
}
func firstLine(b string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(b), "\n")
	return clip(l, 120)
}
func envKeys(b string) []string {
	var ks []string
	for _, l := range strings.Split(b, "\n") {
		if k, _, ok := strings.Cut(strings.TrimSpace(l), "="); ok && regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,}$`).MatchString(k) {
			ks = append(ks, k)
		}
	}
	return ks
}
