// Package correlate normalises RawFindings from many tools into Findings:
// it merges true duplicates (same vulnerability identity) while preserving every
// affected asset and every piece of supporting evidence, calibrates confidence,
// and applies explainable false-positive triage rules.
package correlate

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/risk"
)

// Input to a correlation pass.
type Input struct {
	Raw      []model.RawFinding
	Services []model.Service
	Risk     risk.Context
	Now      time.Time
}

var baseConf = map[model.Basis]float64{
	model.BasisDirect:   0.90,
	model.BasisVersion:  0.50,
	model.BasisReported: 0.60,
}

// Run produces the unified, ranked finding list.
func Run(in Input) []model.Finding {
	groups := map[string]*model.Finding{}
	perTool := map[string]map[string]float64{} // key -> tool -> best confidence
	var order []string
	svcByHostPort := map[string]model.Service{}
	for _, s := range in.Services {
		k := fmt.Sprintf("%s:%d", s.Host, s.Port)
		if prev, ok := svcByHostPort[k]; !ok || prev.State != "open" {
			svcByHostPort[k] = s
		}
	}
	cveKey := map[string]string{} // any CVE seen -> group key, so tools citing different CVEs of one issue still merge
	for _, r := range in.Raw {
		key := identity(r)
		for _, c := range r.CVEs {
			if k, ok := cveKey[strings.ToUpper(c)]; ok && strings.HasPrefix(key, "cve:") || ok && r.Key == "" {
				key = k
				break
			}
		}
		for _, c := range r.CVEs {
			if _, ok := cveKey[strings.ToUpper(c)]; !ok {
				cveKey[strings.ToUpper(c)] = key
			}
		}
		f, ok := groups[key]
		if !ok {
			f = &model.Finding{Key: key, Title: r.Title, Description: r.Description, Severity: r.Severity,
				OWASP: r.OWASP, Remediation: r.Remediation, Basis: r.Basis, ExploitAvail: "unknown",
				FirstSeen: in.Now, LastSeen: in.Now, Validation: "not_validated"}
			groups[key] = f
			perTool[key] = map[string]float64{}
			order = append(order, key)
		}
		// Severity: keep highest reported; CVSS: keep highest reported and remember its source.
		if model.SevRank(r.Severity) > model.SevRank(f.Severity) {
			f.Severity = r.Severity
		}
		if r.CVSS != nil && (f.CVSS == nil || *r.CVSS > *f.CVSS) {
			v := *r.CVSS
			f.CVSS, f.CVSSVector, f.CVSSSource = &v, r.CVSSVector, r.Tool
		}
		if len(r.Description) > len(f.Description) {
			f.Description = r.Description
		}
		if f.Remediation == "" {
			f.Remediation = r.Remediation
		}
		if f.OWASP == "" {
			f.OWASP = r.OWASP
		}
		f.CVEs = union(f.CVEs, r.CVEs)
		f.CWEs = union(f.CWEs, r.CWEs)
		f.References = union(f.References, r.References)
		f.Tools = union(f.Tools, []string{r.Tool})
		if r.Basis == model.BasisDirect {
			f.Basis = model.BasisDirect // strongest basis wins
		}
		if r.ExploitAvail != nil {
			if *r.ExploitAvail {
				f.ExploitAvail = "yes"
			} else if f.ExploitAvail != "yes" {
				f.ExploitAvail = "no"
			}
		}
		if r.Evidence != "" {
			f.Evidence = union(f.Evidence, []string{r.Evidence})
		}
		// Asset entry (distinct assets are never hidden).
		var a *model.Affected
		for i := range f.Assets {
			if f.Assets[i].Host == r.Host && f.Assets[i].Port == r.Port {
				a = &f.Assets[i]
			}
		}
		if a == nil {
			f.Assets = append(f.Assets, model.Affected{Host: r.Host, Port: r.Port})
			a = &f.Assets[len(f.Assets)-1]
			if s, ok := svcByHostPort[fmt.Sprintf("%s:%d", r.Host, r.Port)]; ok {
				a.Service = s.Name
			}
		}
		a.Tools = union(a.Tools, []string{r.Tool})
		if r.Evidence != "" {
			a.Evidence = union(a.Evidence, []string{r.Evidence})
		}
		c := baseConf[r.Basis]
		if r.ToolConf != nil {
			c = (c + *r.ToolConf) / 2
		}
		if c > perTool[key][r.Tool] {
			perTool[key][r.Tool] = c
		}
	}
	var out []model.Finding
	for _, key := range order {
		f := groups[key]
		calibrate(f, perTool[key])
		triage(f, svcByHostPort, in.Services)
		sort.Slice(f.Assets, func(i, j int) bool {
			if f.Assets[i].Host != f.Assets[j].Host {
				return f.Assets[i].Host < f.Assets[j].Host
			}
			return f.Assets[i].Port < f.Assets[j].Port
		})
		sort.Strings(f.Tools)
		risk.Score(f, in.Risk)
		out = append(out, *f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Risk.Score != out[j].Risk.Score {
			return out[i].Risk.Score > out[j].Risk.Score
		}
		return out[i].Confidence > out[j].Confidence
	})
	for i := range out {
		out[i].ID = fmt.Sprintf("F-%03d", i+1)
	}
	return out
}

// identity decides what "the same vulnerability" means across tools.
func identity(r model.RawFinding) string {
	if r.Key != "" {
		return strings.ToLower(r.Key)
	}
	if len(r.CVEs) > 0 {
		c := append([]string(nil), r.CVEs...)
		sort.Strings(c)
		return "cve:" + strings.ToLower(c[0])
	}
	return "title:" + strings.ToLower(strings.Join(strings.Fields(r.Title), " "))
}

// calibrate combines independent tools: c = 1 - prod(1 - c_i), capped.
func calibrate(f *model.Finding, byTool map[string]float64) {
	p := 1.0
	for _, c := range byTool {
		p *= 1 - c
	}
	c := 1 - p
	if len(byTool) > 1 {
		f.Notes = append(f.Notes, fmt.Sprintf("Corroborated by %d independent tools (%s); confidence raised accordingly.", len(byTool), strings.Join(f.Tools, ", ")))
	}
	f.Confidence = math.Min(c, 0.97)
	switch {
	case f.Confidence >= 0.85:
		f.ConfLabel = "high"
	case f.Confidence >= 0.6:
		f.ConfLabel = "medium"
	default:
		f.ConfLabel = "low"
	}
	// "Confirmed" requires direct observation of the condition. A version match,
	// even from two tools, stays "suspected" until validated.
	if f.Basis == model.BasisDirect && f.Confidence >= 0.85 {
		f.Status = "confirmed"
	} else {
		f.Status = "suspected"
	}
}

// triage applies explainable, rule-based false-positive checks.
func triage(f *model.Finding, byHP map[string]model.Service, all []model.Service) {
	// Rule 1: contradiction. Our own probe saw the port closed/filtered.
	var contradicted []string
	for _, a := range f.Assets {
		if a.Port == 0 {
			continue
		}
		if s, ok := byHP[fmt.Sprintf("%s:%d", a.Host, a.Port)]; ok && s.State != "open" && s.State != "" {
			contradicted = append(contradicted, fmt.Sprintf("%s:%d", a.Host, a.Port))
		}
	}
	if len(contradicted) > 0 && len(contradicted) == len(f.Assets) {
		f.Status = "likely_false_positive"
		f.Confidence *= 0.4
		f.ConfLabel = "low"
		f.Notes = append(f.Notes, "Triage: our own probe observed "+strings.Join(contradicted, ", ")+" as not open, contradicting this finding. Verify before reporting.")
	}
	// Rule 2: version-only inference on a distro-packaged banner (patches are often back-ported).
	if f.Basis == model.BasisVersion && len(f.Tools) == 1 {
		for _, a := range f.Assets {
			if s, ok := byHP[fmt.Sprintf("%s:%d", a.Host, a.Port)]; ok {
				b := strings.ToLower(s.Banner + " " + s.Product + " " + s.Version)
				for _, d := range []string{"debian", "ubuntu", "centos", "red hat", "rhel", "+deb", "~ubuntu"} {
					if strings.Contains(b, d) {
						f.Confidence *= 0.7
						f.Notes = append(f.Notes, "Triage: finding is inferred from a version string on a distribution-packaged service; security fixes are frequently back-ported without changing the version, so this may not be exploitable. Confidence reduced.")
						goto done
					}
				}
			}
		}
	}
done:
	if f.Confidence < 0.6 && f.ConfLabel != "low" {
		f.ConfLabel = "low"
	}
	if f.Basis != model.BasisDirect && f.Status == "suspected" {
		f.Notes = append(f.Notes, "Status is 'suspected': not directly observed by this assessment and not yet validated.")
	}
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
