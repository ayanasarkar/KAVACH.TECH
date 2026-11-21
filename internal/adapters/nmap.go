package adapters

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// Nmap runs the real nmap binary (-sV) and parses its XML. Live only when nmap
// is installed; otherwise the run fails safely and the agent falls back.
type Nmap struct{}

func (*Nmap) Name() string     { return "nmap" }
func (*Nmap) Mode() Mode       { return Live }
func (*Nmap) Kind() scope.Kind { return scope.KindActive }
func (*Nmap) Describe() string {
	return "Host/port/service discovery with version detection via the nmap CLI (XML output)."
}
func (*Nmap) Available() (bool, string) { return have("nmap") }

type nmapRun struct {
	Hosts []struct {
		Addrs []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports []struct {
			Proto string `xml:"protocol,attr"`
			ID    int    `xml:"portid,attr"`
			State struct {
				S string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name, Product, Version, Extra string
				N                             string `xml:"name,attr"`
				P                             string `xml:"product,attr"`
				V                             string `xml:"version,attr"`
				E                             string `xml:"extrainfo,attr"`
				Tunnel                        string `xml:"tunnel,attr"`
			} `xml:"service"`
			Scripts []struct {
				ID  string `xml:"id,attr"`
				Out string `xml:"output,attr"`
			} `xml:"script"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

// nmapServiceName normalises nmap's service name. nmap reports a TLS web port as name="http" tunnel="ssl"
// (its own notation is "ssl/http"); the agent labels that https, the same scheme webcheck negotiates, so a
// finding's asset line never contradicts the Assets Tested table.
func nmapServiceName(name, tunnel string) string {
	if tunnel == "ssl" && name == "http" {
		return "https"
	}
	return name
}

func (*Nmap) Run(ctx context.Context, j Job) (Result, error) {
	if err := validHost(j.Host); err != nil {
		return Result{}, err
	}
	ports := j.Options["ports"]
	args := []string{"-sV", "--version-light", "-T3", "-Pn", "-oX", "-"}
	switch {
	case ports != "" && ports != "top":
		list := parsePorts(ports, j.AllowPort)
		if len(list) == 0 {
			return Result{}, fmt.Errorf("no ports to scan after applying the scope port list")
		}
		args = append(args, "-p", strings.Join(intsToStr(list), ","))
	case j.Port != 0:
		if j.AllowPort != nil && !j.AllowPort(j.Port) {
			return Result{}, fmt.Errorf("port %d is not in the authorised port list", j.Port)
		}
		args = append(args, "-p", strconv.Itoa(j.Port))
	case len(j.AllowedPorts) > 0:
		// The scope restricts ports: a default sweep must stay inside that list, never --top-ports.
		args = append(args, "-p", strings.Join(intsToStr(j.AllowedPorts), ","))
	default:
		// -p and --top-ports cannot be combined (-p wins), so the default sweep is one explicit list:
		// nmap's own top 100 plus the agent's sweep list, so nmap covers every port the built-in scanner does.
		list := sweepPorts(j.AllowPort)
		if len(list) == 0 {
			return Result{}, fmt.Errorf("no ports to scan after applying the scope port list")
		}
		args = append(args, "-p", strings.Join(intsToStr(list), ","))
	}
	if j.MaxReqPerSec > 0 {
		args = append(args, "--max-rate", strconv.Itoa(j.MaxReqPerSec))
	}
	scripts := "banner" // raw greeting: -sV alone reports nothing for a product it does not recognise
	if j.Options["scripts"] == "vulners" {
		scripts = "banner,vulners"
	}
	args = append(args, "--script", scripts)
	target, v6, perr := j.pinnedAddr()
	if perr != nil {
		return Result{}, perr
	}
	if v6 {
		args = append(args, "-6")
	}
	args = append(args, target) // the checked address, not the name: nmap must not resolve it a second time
	out, errOut, err := runCmd(ctx, 5*time.Minute, "nmap", args...)
	if err != nil {
		return Result{Raw: out + errOut}, err
	}
	var run nmapRun
	if e := xml.Unmarshal([]byte(out), &run); e != nil {
		return Result{Raw: out}, fmt.Errorf("could not parse nmap XML: %w", e)
	}
	res := Result{Raw: out}
	lines := strings.Split(out, "\n")
	lineOf := func(sub string) int {
		for i, l := range lines {
			if strings.Contains(l, sub) {
				return i + 1
			}
		}
		return 0
	}
	for _, h := range run.Hosts {
		addr := j.Host
		for _, a := range h.Addrs {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				addr = a.Addr
			}
		}
		for _, p := range h.Ports {
			ident := strings.TrimSpace(p.Service.P + " " + p.Service.V + " " + p.Service.E)
			banner := ident
			for _, sc := range p.Scripts {
				if sc.ID != "banner" {
					continue
				}
				if raw := nmapBannerText(sc.Out); raw != "" && !strings.Contains(banner, raw) {
					banner = strings.TrimSpace(banner + " " + raw)
				}
			}
			svcName := nmapServiceName(p.Service.N, p.Service.Tunnel)
			s := model.Service{Host: j.Host, Port: p.ID, Proto: p.Proto, State: p.State.S, Name: svcName, Product: p.Service.P, Version: p.Service.V, Tool: "nmap",
				Banner: banner}
			res.Services = append(res.Services, s)
			if s.State == "open" {
				excerpt := fmt.Sprintf("%s:%d/%s open service=%s product=%q", s.Host, s.Port, s.Proto, s.Name, s.Product)
				if f, ok := exposureFinding("nmap", s, excerpt, fmt.Sprintf("line %d", lineOf(fmt.Sprintf("portid=\"%d\"", p.ID)))); ok {
					res.Findings = append(res.Findings, f)
				}
			}
			for _, sc := range p.Scripts {
				if sc.ID != "vulners" {
					continue
				}
				for _, l := range strings.Split(sc.Out, "\n") {
					f := strings.Fields(l)
					for i, tok := range f {
						if cves := FindCVEs(tok); len(cves) == 1 && strings.EqualFold(tok, cves[0]) && i+1 < len(f) {
							if sc, e := strconv.ParseFloat(f[i+1], 64); e == nil {
								res.Findings = append(res.Findings, model.RawFinding{Tool: "nmap", Key: "cve:" + strings.ToLower(cves[0]),
									Title: cves[0] + " reported for " + ident, Host: j.Host, Port: p.ID, Proto: p.Proto, CVEs: cves,
									Severity: sevFromCVSS(sc), CVSS: fptr(sc), Basis: model.BasisVersion,
									Description: "nmap's vulners script matched the detected product/version against a vulnerability database. This is a version match, not proof of exploitability.",
									Excerpt:     strings.TrimSpace(l), RawRef: fmt.Sprintf("line %d", lineOf(cves[0]))})
							}
						}
					}
				}
			}
		}
		_ = addr
	}
	open := 0
	for _, s := range res.Services {
		if s.State == "open" {
			open++
		}
	}
	res.Summary = fmt.Sprintf("%d services found, %d open", len(res.Services), open)
	return res, nil
}

func intsToStr(in []int) []string {
	var o []string
	for _, i := range in {
		o = append(o, strconv.Itoa(i))
	}
	return o
}

// nmapTop100 is nmap's own --top-ports 100 list (nmap 7.94).
var nmapTop100 = []int{7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157}

// sweepPorts is the default nmap sweep: the agent's own list first, then nmap's top 100, without
// duplicates and inside the scope's port allow-list.
func sweepPorts(allow func(int) bool) []int {
	seen := map[int]bool{}
	var out []int
	for _, list := range [][]int{topPorts, nmapTop100} {
		for _, p := range list {
			if seen[p] || (allow != nil && !allow(p)) {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// nmapBannerText cleans the output of nmap's banner script. nmap hard-wraps script output at 63 columns,
// which can split a word in two, so its newlines are layout: they are removed, not turned into spaces.
// Control characters are dropped. nmap itself cuts long banners (about 130 characters).
func nmapBannerText(s string) string {
	s = strings.NewReplacer("\r", "", "\n", "").Replace(s)
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

func sevFromCVSS(s float64) string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 4:
		return "medium"
	case s > 0:
		return "low"
	}
	return "info"
}
