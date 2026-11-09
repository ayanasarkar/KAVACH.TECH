package adapters

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// The import adapters read exports produced by commercial/enterprise tools.
// They never contact the tool: they are import-only and say so in the matrix.
// Go's encoding/xml does not resolve external entities, so XXE is not possible.

func walk(b []byte, element string, fn func(*xml.Decoder, xml.StartElement) error) error {
	d := xml.NewDecoder(bytes.NewReader(b))
	for {
		t, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("XML parse error: %w", err)
		}
		if se, ok := t.(xml.StartElement); ok && se.Name.Local == element {
			if err := fn(d, se); err != nil {
				return err
			}
		}
	}
}

var tagRe = regexp.MustCompile(`<[^>]+>`)

func stripHTML(s string) string {
	return strings.Join(strings.Fields(tagRe.ReplaceAllString(s, " ")), " ")
}

func attr(se xml.StartElement, n string) string {
	for _, a := range se.Attr {
		if a.Name.Local == n {
			return a.Value
		}
	}
	return ""
}

// ---------- Nessus (.nessus v2) ----------

type Nessus struct{}

func (*Nessus) Name() string     { return "nessus" }
func (*Nessus) Mode() Mode       { return ImportOnl }
func (*Nessus) Kind() scope.Kind { return scope.KindPassive }
func (*Nessus) Describe() string {
	return "Imports a Nessus v2 (.nessus) export. No live API: Nessus is commercial and requires the analyst's own licence."
}
func (*Nessus) Available() (bool, string) { return true, "import-only: upload a .nessus file" }

type nessusItem struct {
	Port     int      `xml:"port,attr"`
	Svc      string   `xml:"svc_name,attr"`
	Proto    string   `xml:"protocol,attr"`
	Sev      int      `xml:"severity,attr"`
	PluginID string   `xml:"pluginID,attr"`
	Name     string   `xml:"pluginName,attr"`
	Synopsis string   `xml:"synopsis"`
	Desc     string   `xml:"description"`
	Solution string   `xml:"solution"`
	Risk     string   `xml:"risk_factor"`
	CVSS3    string   `xml:"cvss3_base_score"`
	CVSS     string   `xml:"cvss_base_score"`
	V3Vec    string   `xml:"cvss3_vector"`
	CVEs     []string `xml:"cve"`
	CWEs     []string `xml:"cwe"`
	Exploit  string   `xml:"exploit_available"`
	Output   string   `xml:"plugin_output"`
	SeeAlso  string   `xml:"see_also"`
}

func (*Nessus) Run(_ context.Context, j Job) (Result, error) {
	b, err := readImport(j.ImportPath)
	if err != nil {
		return Result{}, err
	}
	res := Result{Raw: string(b)}
	lines := strings.Split(res.Raw, "\n")
	sevName := []string{"info", "low", "medium", "high", "critical"}
	err = walk(b, "ReportHost", func(d *xml.Decoder, se xml.StartElement) error {
		host := attr(se, "name")
		var rh struct {
			Items []nessusItem `xml:"ReportItem"`
		}
		if err := d.DecodeElement(&rh, &se); err != nil {
			return err
		}
		for _, it := range rh.Items {
			sev := "info"
			if it.Sev >= 0 && it.Sev < len(sevName) {
				sev = sevName[it.Sev]
			}
			var cv *float64
			vec := ""
			for _, s := range []string{it.CVSS3, it.CVSS} {
				if f, e := strconv.ParseFloat(strings.TrimSpace(s), 64); e == nil && cv == nil {
					cv = fptr(f)
				}
			}
			if it.CVSS3 != "" {
				vec = it.V3Vec
			}
			cves := dedupe(it.CVEs)
			key := NormalizeKey(it.Name, it.Synopsis)
			if key == "" && len(cves) > 0 {
				key = "cve:" + strings.ToLower(cves[0])
			}
			if key == "" {
				key = "nessus:plugin:" + it.PluginID
			}
			ex := strings.TrimSpace(it.Output)
			if ex == "" {
				ex = it.Synopsis
			}
			ref := fmt.Sprintf("host %s plugin %s", host, it.PluginID)
			for i, l := range lines {
				if strings.Contains(l, `pluginID="`+it.PluginID+`"`) {
					ref += fmt.Sprintf(" (file line %d)", i+1)
					break
				}
			}
			var ea *bool
			if it.Exploit != "" {
				ea = bptr(strings.EqualFold(strings.TrimSpace(it.Exploit), "true"))
			}
			res.Findings = append(res.Findings, model.RawFinding{Tool: "nessus", Key: key, Title: it.Name, Description: clip(it.Desc, 700), Host: host, Port: it.Port,
				Proto: it.Proto, Severity: sev, CVSS: cv, CVSSVector: vec, CVEs: cves, CWEs: dedupe(append(it.CWEs, FindCWEs(it.Desc)...)),
				Basis: model.BasisReported, ExploitAvail: ea, Remediation: clip(it.Solution, 500), References: strings.Fields(it.SeeAlso),
				Excerpt: clip(ex, 400), RawRef: ref})
			if it.Port != 0 && it.Svc != "" && sev != "info" || it.Port != 0 && it.Sev == 0 && it.Svc != "" {
				res.Services = append(res.Services, model.Service{Host: host, Port: it.Port, Proto: it.Proto, State: "open", Name: it.Svc, Tool: "nessus"})
			}
		}
		return nil
	})
	res.Summary = fmt.Sprintf("%d Nessus results imported", len(res.Findings))
	if err == nil && len(res.Findings) == 0 {
		err = fmt.Errorf("no ReportItem entries found: is this a Nessus v2 (.nessus) file?")
	}
	return res, err
}

// ---------- OpenVAS / Greenbone XML report ----------

type OpenVAS struct{}

func (*OpenVAS) Name() string     { return "openvas" }
func (*OpenVAS) Mode() Mode       { return ImportOnl }
func (*OpenVAS) Kind() scope.Kind { return scope.KindPassive }
func (*OpenVAS) Describe() string {
	return "Imports a Greenbone/OpenVAS XML report (gvm-cli / web UI export). No live GMP session."
}
func (*OpenVAS) Available() (bool, string) { return true, "import-only: upload a Greenbone XML report" }

func (*OpenVAS) Run(_ context.Context, j Job) (Result, error) {
	b, err := readImport(j.ImportPath)
	if err != nil {
		return Result{}, err
	}
	res := Result{Raw: string(b)}
	lines := strings.Split(res.Raw, "\n")
	err = walk(b, "result", func(d *xml.Decoder, se xml.StartElement) error {
		var r struct {
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
			Host struct {
				Text string `xml:",chardata"`
			} `xml:"host"`
			Port string `xml:"port"`
			NVT  struct {
				OID      string `xml:"oid,attr"`
				CVSS     string `xml:"cvss_base"`
				Solution string `xml:"solution"`
				Tags     string `xml:"tags"`
				Refs     []struct {
					Type string `xml:"type,attr"`
					ID   string `xml:"id,attr"`
				} `xml:"refs>ref"`
			} `xml:"nvt"`
			Sev  string `xml:"severity"`
			QoD  string `xml:"qod>value"`
			Desc string `xml:"description"`
		}
		if err := d.DecodeElement(&r, &se); err != nil {
			return err
		}
		if r.Name == "" {
			return nil
		}
		host := strings.TrimSpace(r.Host.Text)
		port, proto := 0, "tcp"
		if p, pr, ok := strings.Cut(strings.TrimSpace(r.Port), "/"); ok {
			port, _ = strconv.Atoi(p)
			proto = pr
		}
		score, e := strconv.ParseFloat(strings.TrimSpace(r.Sev), 64)
		if e != nil {
			score, _ = strconv.ParseFloat(strings.TrimSpace(r.NVT.CVSS), 64)
		}
		var cves, cwes []string
		for _, ref := range r.NVT.Refs {
			if strings.EqualFold(ref.Type, "cve") {
				cves = append(cves, strings.ToUpper(ref.ID))
			}
		}
		cves = dedupe(append(cves, FindCVEs(r.Desc)...))
		cwes = FindCWEs(r.Desc + r.NVT.Tags)
		var tc *float64
		if q, e := strconv.ParseFloat(strings.TrimSpace(r.QoD), 64); e == nil {
			tc = fptr(q / 100) // OpenVAS reports Quality of Detection in %
		}
		key := NormalizeKey(r.Name, "")
		if key == "" && len(cves) > 0 {
			key = "cve:" + strings.ToLower(cves[0])
		}
		if key == "" {
			key = "openvas:nvt:" + r.NVT.OID
		}
		ref := "result id " + r.ID
		for i, l := range lines {
			if strings.Contains(l, `id="`+r.ID+`"`) {
				ref += fmt.Sprintf(" (file line %d)", i+1)
				break
			}
		}
		fc := &score
		if score == 0 {
			fc = nil
		}
		basis := model.BasisReported
		res.Findings = append(res.Findings, model.RawFinding{Tool: "openvas", Key: key, Title: r.Name, Description: clip(r.Desc, 700), Host: host, Port: port, Proto: proto,
			Severity: sevFromCVSS(score), CVSS: fc, CVEs: cves, CWEs: cwes, Basis: basis, ToolConf: tc, Remediation: clip(r.NVT.Solution, 500),
			Excerpt: clip(r.Desc, 400), RawRef: ref})
		return nil
	})
	res.Summary = fmt.Sprintf("%d OpenVAS results imported", len(res.Findings))
	if err == nil && len(res.Findings) == 0 {
		err = fmt.Errorf("no <result> entries found: is this a Greenbone XML report?")
	}
	return res, err
}

// ---------- Burp Suite XML issue export ----------

type Burp struct{}

func (*Burp) Name() string     { return "burp" }
func (*Burp) Mode() Mode       { return ImportOnl }
func (*Burp) Kind() scope.Kind { return scope.KindPassive }
func (*Burp) Describe() string {
	return "Imports a Burp Suite issues XML export. Burp Community has no scanner/REST API and Burp Pro/DAST licences are the analyst's own."
}
func (*Burp) Available() (bool, string) { return true, "import-only: upload a Burp issues XML export" }

func (*Burp) Run(_ context.Context, j Job) (Result, error) {
	b, err := readImport(j.ImportPath)
	if err != nil {
		return Result{}, err
	}
	res := Result{Raw: string(b)}
	lines := strings.Split(res.Raw, "\n")
	sev := map[string]string{"high": "high", "medium": "medium", "low": "low", "information": "info", "info": "info"}
	conf := map[string]float64{"certain": 0.95, "firm": 0.75, "tentative": 0.4}
	err = walk(b, "issue", func(d *xml.Decoder, se xml.StartElement) error {
		var is struct {
			Serial string `xml:"serialNumber"`
			Name   string `xml:"name"`
			Host   struct {
				IP   string `xml:"ip,attr"`
				Text string `xml:",chardata"`
			} `xml:"host"`
			Path   string `xml:"path"`
			Sev    string `xml:"severity"`
			Conf   string `xml:"confidence"`
			Bg     string `xml:"issueBackground"`
			Rem    string `xml:"remediationBackground"`
			Detail string `xml:"issueDetail"`
			Class  string `xml:"vulnerabilityClassifications"`
		}
		if err := d.DecodeElement(&is, &se); err != nil {
			return err
		}
		if is.Name == "" {
			return nil
		}
		host, port := is.Host.IP, 0
		if host == "" {
			host = is.Host.Text
		}
		if h, p, e := splitURLHostPort(is.Host.Text); e == nil {
			if is.Host.IP == "" {
				host = h
			}
			port = p
		}
		c := conf[strings.ToLower(is.Conf)]
		cl := stripHTML(is.Class)
		key := NormalizeKey(is.Name, is.Detail)
		cves := FindCVEs(cl)
		if key == "" && len(cves) > 0 {
			key = "cve:" + strings.ToLower(cves[0])
		}
		if key == "" {
			key = "burp:" + strings.ToLower(is.Name)
		}
		ref := "issue serial " + is.Serial
		for i, l := range lines {
			if strings.Contains(l, "<serialNumber>"+is.Serial+"</serialNumber>") {
				ref += fmt.Sprintf(" (file line %d)", i+1)
				break
			}
		}
		res.Findings = append(res.Findings, model.RawFinding{Tool: "burp", Key: key, Title: is.Name, Description: clip(stripHTML(is.Bg+" "+is.Detail), 700),
			Host: host, Port: port, Proto: "tcp", Severity: sev[strings.ToLower(strings.TrimSpace(is.Sev))], CVEs: cves, CWEs: FindCWEs(cl),
			Basis: model.BasisReported, ToolConf: &c, Remediation: clip(stripHTML(is.Rem), 500),
			Excerpt: clip(stripHTML(is.Detail), 400) + " [path " + is.Path + "]", RawRef: ref})
		return nil
	})
	res.Summary = fmt.Sprintf("%d Burp issues imported", len(res.Findings))
	if err == nil && len(res.Findings) == 0 {
		err = fmt.Errorf("no <issue> entries found: is this a Burp XML issue export?")
	}
	return res, err
}

func splitURLHostPort(u string) (string, int, error) {
	h, p, err := scope.SplitTarget(strings.TrimSpace(u))
	return h, p, err
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
