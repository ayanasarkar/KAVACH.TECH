package adapters

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// PortScan is a built-in, dependency-free TCP connect scanner with banner grab.
// It runs live everywhere (no external binary) so the pipeline always has real
// reconnaissance data, even when Nmap is not installed.
type PortScan struct{}

func (*PortScan) Name() string     { return "portscan" }
func (*PortScan) Mode() Mode       { return Live }
func (*PortScan) Kind() scope.Kind { return scope.KindActive }
func (*PortScan) Describe() string {
	return "Built-in TCP connect scan + banner grab (no external binary). Fallback recon when Nmap is unavailable."
}
func (*PortScan) Available() (bool, string) { return true, "" }

var topPorts = []int{21, 22, 23, 2121, 2222, 2323, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995,
	1433, 1521, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5900, 5984, 6379, 7001, 8000, 8008, 8080, 8081,
	8088, 8443, 8888, 9000, 9090, 9200, 11211, 27017}

var portNames = map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 110: "pop3",
	111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds",
	465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle", 2375: "docker",
	3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 5984: "couchdb", 6379: "redis",
	9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"}

func parsePorts(spec string, allow func(int) bool) []int {
	var out []int
	add := func(p int) {
		if p > 0 && p < 65536 && (allow == nil || allow(p)) {
			out = append(out, p)
		}
	}
	if spec == "" || spec == "top" {
		for _, p := range topPorts {
			add(p)
		}
		return out
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, _ := strconv.Atoi(a)
			hi, _ := strconv.Atoi(b)
			for p := lo; p <= hi && p-lo < 4096; p++ {
				add(p)
			}
		} else if p, err := strconv.Atoi(part); err == nil {
			add(p)
		}
	}
	return out
}

func (*PortScan) Run(ctx context.Context, j Job) (Result, error) {
	ports := parsePorts(j.Options["ports"], j.AllowPort)
	if j.Port != 0 && (j.Options["ports"] == "") {
		ports = []int{j.Port}
	}
	if len(ports) == 0 {
		return Result{}, fmt.Errorf("no ports to scan after applying the scope port list")
	}
	var (
		mu   sync.Mutex
		svcs []model.Service
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 32)
	)
	var raw strings.Builder
	fmt.Fprintf(&raw, "# portscan target=%s ports=%d started=%s\n", j.Host, len(ports), time.Now().UTC().Format(time.RFC3339))
	for _, p := range ports {
		select {
		case <-ctx.Done():
			wg.Wait()
			return Result{}, ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			j.Limiter.Wait()
			s := probe(ctx, j, p)
			mu.Lock()
			svcs = append(svcs, s)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Slice(svcs, func(a, b int) bool { return svcs[a].Port < svcs[b].Port })
	var res Result
	open := 0
	for _, s := range svcs {
		fmt.Fprintf(&raw, "%s:%d/tcp %s service=%s banner=%q\n", s.Host, s.Port, s.State, s.Name, s.Banner)
		if s.State == "open" {
			open++
		}
	}
	res.Raw = raw.String()
	res.Services = svcs
	line := map[int]int{}
	for i, l := range strings.Split(res.Raw, "\n") {
		if strings.HasPrefix(l, j.Host+":") {
			if p, err := strconv.Atoi(strings.SplitN(strings.TrimPrefix(l, j.Host+":"), "/", 2)[0]); err == nil {
				line[p] = i + 1
			}
		}
	}
	for _, s := range svcs {
		if s.State != "open" {
			continue
		}
		ref := fmt.Sprintf("line %d", line[s.Port])
		excerpt := fmt.Sprintf("%s:%d/tcp open service=%s banner=%q", s.Host, s.Port, s.Name, s.Banner)
		switch s.Name {
		case "telnet":
			res.Findings = append(res.Findings, model.RawFinding{Tool: "portscan", Key: "net:cleartext:telnet",
				Title: "Telnet service exposed (cleartext remote administration)", Host: s.Host, Port: s.Port, Proto: "tcp",
				Severity: "high", Basis: model.BasisDirect, CWEs: []string{"CWE-319"}, OWASP: "A02:2021 Cryptographic Failures",
				Description: "A Telnet service accepted a TCP connection. Telnet transmits credentials and session data without encryption.",
				Remediation: "Disable Telnet and use SSH with key-based authentication. Restrict management ports to an admin network.",
				References:  []string{"https://cwe.mitre.org/data/definitions/319.html"}, Excerpt: excerpt, RawRef: ref})
		case "ftp":
			res.Findings = append(res.Findings, model.RawFinding{Tool: "portscan", Key: "net:cleartext:ftp",
				Title: "FTP service exposed (cleartext file transfer)", Host: s.Host, Port: s.Port, Proto: "tcp",
				Severity: "medium", Basis: model.BasisDirect, CWEs: []string{"CWE-319"}, OWASP: "A02:2021 Cryptographic Failures",
				Description: "An FTP service accepted a TCP connection. Plain FTP transmits credentials and data without encryption.",
				Remediation: "Replace FTP with SFTP or FTPS and disable anonymous access unless explicitly required.",
				References:  []string{"https://cwe.mitre.org/data/definitions/319.html"}, Excerpt: excerpt, RawRef: ref})
		case "redis", "memcached", "mongodb", "elasticsearch", "couchdb", "mysql", "postgresql", "ms-sql-s", "docker":
			res.Findings = append(res.Findings, model.RawFinding{Tool: "portscan", Key: "net:exposed-datastore:" + s.Name,
				Title: fmt.Sprintf("Data service %s reachable over the network", s.Name), Host: s.Host, Port: s.Port, Proto: "tcp",
				Severity: "medium", Basis: model.BasisDirect, CWEs: []string{"CWE-284"}, OWASP: "A05:2021 Security Misconfiguration",
				Description: "A database/management service accepted a TCP connection from the assessment host. Whether authentication is enforced was NOT tested by this check.",
				Remediation: "Bind data services to localhost or a private management network, require authentication and restrict access with host firewalls.",
				Excerpt:     excerpt, RawRef: ref})
		}
		if s.Banner != "" && (strings.Contains(strings.ToLower(s.Banner), "/") || strings.ContainsAny(s.Banner, "0123456789")) && s.Name != "http" && s.Name != "https" {
			res.Findings = append(res.Findings, model.RawFinding{Tool: "portscan", Key: fmt.Sprintf("net:banner-disclosure:%s", s.Name),
				Title: fmt.Sprintf("Service banner discloses software details (%s)", s.Name), Host: s.Host, Port: s.Port, Proto: "tcp",
				Severity: "info", Basis: model.BasisDirect, CWEs: []string{"CWE-200"}, OWASP: "A05:2021 Security Misconfiguration",
				Description: "The service announces product/version information to unauthenticated clients, aiding attacker reconnaissance.",
				Remediation: "Suppress or genericise service banners where the product allows it.", Excerpt: excerpt, RawRef: ref})
		}
	}
	res.Summary = fmt.Sprintf("%d ports probed, %d open", len(ports), open)
	return res, nil
}

func probe(ctx context.Context, j Job, port int) model.Service {
	host := j.Host
	s := model.Service{Host: host, Port: port, Proto: "tcp", State: "closed", Tool: "portscan", Name: portNames[port]}
	d := j.dialer(1500 * time.Millisecond)
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			s.State = "filtered"
		}
		return s
	}
	defer c.Close()
	s.State = "open"
	c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := c.Read(buf)
	if n == 0 && (port == 80 || port == 8080 || port == 8000 || port == 8008 || port == 8081 || port == 8088 || port == 8888 || port == 3000 || port == 5000 || port == 9000 || port == 9090) {
		c.SetWriteDeadline(time.Now().Add(700 * time.Millisecond))
		c.Write([]byte("HEAD / HTTP/1.0\r\nUser-Agent: vapt-agent\r\n\r\n"))
		c.SetReadDeadline(time.Now().Add(900 * time.Millisecond))
		n, _ = c.Read(buf)
	}
	telnetIAC := n >= 2 && buf[0] == 0xff && buf[1] >= 0xfb // IAC WILL/WONT/DO/DONT negotiation
	b := strings.TrimSpace(string(buf[:n]))
	if i := strings.IndexAny(b, "\r\n"); i >= 0 && !strings.HasPrefix(b, "HTTP/") {
		b = b[:i]
	}
	s.Banner = clip(printable(b), 160)
	switch {
	case strings.HasPrefix(b, "HTTP/"):
		s.Name = "http"
		for _, l := range strings.Split(b, "\n") {
			if strings.HasPrefix(strings.ToLower(l), "server:") {
				s.Product = strings.TrimSpace(l[7:])
			}
		}
		s.Banner = s.Banner[:min(len(s.Banner), 120)]
	case telnetIAC:
		s.Name = "telnet"
	case strings.HasPrefix(b, "SSH-"):
		s.Name = "ssh"
	case strings.HasPrefix(b, "220") && strings.Contains(strings.ToLower(b), "ftp"):
		s.Name = "ftp"
	case strings.HasPrefix(b, "220") && port != 21:
		s.Name = "smtp"
	}
	if s.Name == "" {
		s.Name = "unknown"
	}
	return s
}

func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, s)
}
