// Package risk computes prioritisation scores in code. The LLM never supplies
// a CVE, CVSS value or risk score; every input here comes from tool output or
// from the analyst-supplied asset criticality.
package risk

import (
	"fmt"
	"math"

	"github.com/ayanasarkar/vapt-agent/internal/model"
)

// Context carries analyst-provided and observed context.
type Context struct {
	// Criticality maps host -> low|medium|high|critical (analyst input). Default medium.
	Criticality map[string]string
	// ReachableFrom describes how the assessment reached the asset, e.g. "network".
	Reachable map[string]bool // host:port -> observed reachable by our own probe
}

var nominal = map[string]float64{"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5, "info": 0}

var impactMul = map[string]float64{"low": 0.8, "medium": 1.0, "high": 1.15, "critical": 1.3}

// Score fills f.Risk.
func Score(f *model.Finding, c Context) {
	var fac []model.Factor
	base := 0.0
	if f.CVSS != nil {
		base = *f.CVSS
		fac = append(fac, model.Factor{Name: "base", Value: base, Source: fmt.Sprintf("CVSS %.1f reported by %s", base, f.CVSSSource)})
	} else {
		base = nominal[f.Severity]
		fac = append(fac, model.Factor{Name: "base", Value: base, Source: fmt.Sprintf("no CVSS reported; nominal value for tool-reported severity %q", f.Severity)})
	}
	// Exposure: a service we reached over the network ourselves is observably exposed.
	exp := 0.9
	src := "reachability not observed directly by this assessment"
	reached := false
	for _, a := range f.Assets {
		if c.Reachable[fmt.Sprintf("%s:%d", a.Host, a.Port)] {
			reached = true
		}
	}
	if reached {
		exp, src = 1.0, "service reached over the network by our own probe"
	}
	fac = append(fac, model.Factor{Name: "exposure", Value: exp, Source: src})
	// Exploitability: only from tool-reported data.
	x, xs := 1.0, "no exploit information reported by any tool"
	switch f.ExploitAvail {
	case "yes":
		x, xs = 1.15, "a tool reports a public exploit is available"
	case "no":
		x, xs = 0.95, "tool reports no known public exploit"
	}
	fac = append(fac, model.Factor{Name: "exploitability", Value: x, Source: xs})
	// Asset impact: analyst criticality, highest across affected assets.
	imp, is := 1.0, "default asset criticality: medium"
	best := 0.0
	for _, a := range f.Assets {
		if cr, ok := c.Criticality[a.Host]; ok && impactMul[cr] > best {
			best = impactMul[cr]
			imp, is = best, fmt.Sprintf("analyst-set criticality %q for %s", cr, a.Host)
		}
	}
	fac = append(fac, model.Factor{Name: "asset_impact", Value: imp, Source: is})
	cw := 0.5 + 0.5*f.Confidence
	fac = append(fac, model.Factor{Name: "confidence_weight", Value: round2(cw), Source: fmt.Sprintf("0.5 + 0.5 x confidence %.2f", f.Confidence)})
	score := base * 10 * exp * x * imp * cw
	if f.Status == "likely_false_positive" {
		score *= 0.3
		fac = append(fac, model.Factor{Name: "false_positive_penalty", Value: 0.3, Source: "triage flagged as likely false positive"})
	}
	score = softCap(score)
	f.Risk = model.Risk{Score: round1(score), Priority: priority(score), Factors: fac}
}

// softCap leaves scores up to 80 untouched and compresses the excess smoothly towards 100. A hard cap
// made every high-CVSS finding on a critical asset score exactly 100, so CVSS 9.8 and 8.1 tied and the
// ranking lost all discrimination at the top. This keeps the order strictly monotonic.
func softCap(s float64) float64 {
	const knee = 80.0
	if s <= knee {
		return s
	}
	return knee + (100-knee)*(1-math.Exp(-(s-knee)/60))
}

func priority(s float64) string {
	switch {
	case s >= 75:
		return "P1"
	case s >= 50:
		return "P2"
	case s >= 25:
		return "P3"
	}
	return "P4"
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
func round2(v float64) float64 { return math.Round(v*100) / 100 }
