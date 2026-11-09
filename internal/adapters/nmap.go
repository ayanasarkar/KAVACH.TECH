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
			} `xml:"service"`
			Scripts []struct {
				ID  string `xml:"id,attr"`
				Out string `xml:"output,attr"`
			} `xml:"script"`
		} `xml:"ports>port"`
	} `xml:"host"`
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
		args = append(args, "--top-ports", "100")
	}
	if j.MaxReqPerSec > 0 {
		args = append(args, "--max-rate", strconv.Itoa(j.MaxReqPerSec))
	}
	if j.Options["scripts"] == "vulners" {
		args = append(args, "--script", "vulners")
	}
	args = append(args, j.Host)
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
			s := model.Service{Host: j.Host, Port: p.ID, Proto: p.Proto, State: p.State.S, Name: p.Service.N, Product: p.Service.P, Version: p.Service.V, Tool: "nmap",
				Banner: strings.TrimSpace(p.Service.P + " " + p.Service.V + " " + p.Service.E)}
			res.Services = append(res.Services, s)
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
									Title: cves[0] + " reported for " + s.Banner, Host: j.Host, Port: p.ID, Proto: p.Proto, CVEs: cves,
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
