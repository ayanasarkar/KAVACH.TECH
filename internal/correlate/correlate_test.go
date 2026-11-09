package correlate

import (
	"strings"
	"testing"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/risk"
)

func f64(v float64) *float64 { return &v }

func run(raw []model.RawFinding, svcs []model.Service) []model.Finding {
	return Run(Input{Raw: raw, Services: svcs, Risk: risk.Context{Reachable: map[string]bool{}}, Now: time.Now()})
}

func TestMergeKeepsEveryAssetAndEvidence(t *testing.T) {
	out := run([]model.RawFinding{
		{Tool: "webcheck", Key: "web:missing-header:x-frame-options", Title: "Missing XFO", Host: "10.0.0.1", Port: 80, Severity: "low", Basis: model.BasisDirect, Evidence: "E-1"},
		{Tool: "webcheck", Key: "web:missing-header:x-frame-options", Title: "Missing XFO", Host: "10.0.0.2", Port: 80, Severity: "low", Basis: model.BasisDirect, Evidence: "E-2"},
		{Tool: "nikto", Key: "web:missing-header:x-frame-options", Title: "anti-clickjacking header", Host: "10.0.0.1", Port: 80, Severity: "low", Basis: model.BasisReported, Evidence: "E-3"},
	}, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 merged finding, got %d", len(out))
	}
	f := out[0]
	if len(f.Assets) != 2 {
		t.Errorf("distinct assets hidden: %+v", f.Assets)
	}
	if len(f.Evidence) != 3 {
		t.Errorf("evidence lost: %v", f.Evidence)
	}
	if len(f.Tools) != 2 {
		t.Errorf("tools = %v", f.Tools)
	}
	if !strings.Contains(strings.Join(f.Notes, " "), "Corroborated") {
		t.Error("no corroboration note")
	}
}

func TestSameCVEAcrossToolsMergesEvenWithDifferentTitles(t *testing.T) {
	out := run([]model.RawFinding{
		{Tool: "nessus", Title: "Apache httpd < 2.4.52 multiple vulns", CVEs: []string{"CVE-2021-44790", "CVE-2021-44224"}, Host: "h", Port: 80, Severity: "critical", CVSS: f64(9.8), Basis: model.BasisReported, Evidence: "E-1"},
		{Tool: "openvas", Title: "Apache HTTP Server mod_lua buffer overflow", CVEs: []string{"CVE-2021-44790"}, Host: "h", Port: 80, Severity: "high", CVSS: f64(9.8), Basis: model.BasisReported, Evidence: "E-2"},
	}, nil)
	if len(out) != 1 {
		t.Fatalf("CVE-sharing reports not merged: %d findings", len(out))
	}
	if out[0].Confidence <= 0.6 {
		t.Errorf("two tools should raise confidence above one tool's base, got %.2f", out[0].Confidence)
	}
	if out[0].Status != "suspected" {
		t.Errorf("version/report-based findings must stay suspected, got %s", out[0].Status)
	}
}

func TestDistinctVulnerabilitiesStaySeparate(t *testing.T) {
	out := run([]model.RawFinding{
		{Tool: "a", Title: "X", CVEs: []string{"CVE-2020-0001"}, Host: "h", Port: 1, Severity: "low", Basis: model.BasisReported},
		{Tool: "b", Title: "Y", CVEs: []string{"CVE-2020-0002"}, Host: "h", Port: 1, Severity: "low", Basis: model.BasisReported},
	}, nil)
	if len(out) != 2 {
		t.Fatalf("different CVEs merged: %d", len(out))
	}
}

func TestContradictionMarksLikelyFalsePositive(t *testing.T) {
	out := run([]model.RawFinding{{Tool: "nessus", Key: "cve:cve-2020-1", Title: "ghost", CVEs: []string{"CVE-2020-1"}, Host: "h", Port: 8443, Severity: "high", Basis: model.BasisReported}},
		[]model.Service{{Host: "h", Port: 8443, State: "closed", Tool: "portscan"}})
	if out[0].Status != "likely_false_positive" {
		t.Fatalf("status = %s", out[0].Status)
	}
	if out[0].Risk.Score >= 30 {
		t.Errorf("false-positive penalty not applied: %.1f", out[0].Risk.Score)
	}
}

func TestBackportCaveatLowersVersionOnlyConfidence(t *testing.T) {
	mk := func(banner string) model.Finding {
		return run([]model.RawFinding{{Tool: "nmap", Key: "cve:cve-2019-1", Title: "v", CVEs: []string{"CVE-2019-1"}, Host: "h", Port: 22, Severity: "high", Basis: model.BasisVersion}},
			[]model.Service{{Host: "h", Port: 22, State: "open", Banner: banner}})[0]
	}
	plain, deb := mk("OpenSSH 7.4"), mk("OpenSSH 7.4p1 Debian 10+deb10u2")
	if !(deb.Confidence < plain.Confidence) {
		t.Errorf("distro banner should lower confidence: %.2f vs %.2f", deb.Confidence, plain.Confidence)
	}
}

func TestDirectObservationIsConfirmedAndNoCVSSIsInvented(t *testing.T) {
	out := run([]model.RawFinding{{Tool: "webcheck", Key: "web:exposed-git", Title: "git", Host: "h", Port: 80, Severity: "high", Basis: model.BasisDirect}}, nil)
	f := out[0]
	if f.Status != "confirmed" {
		t.Errorf("status %s", f.Status)
	}
	if f.CVSS != nil || len(f.CVEs) != 0 {
		t.Error("CVSS/CVE must stay empty when no tool reported one")
	}
	if !strings.Contains(f.Risk.Factors[0].Source, "no CVSS reported") {
		t.Errorf("risk base source should say it is nominal: %q", f.Risk.Factors[0].Source)
	}
}

func TestRankingByComputedRisk(t *testing.T) {
	out := run([]model.RawFinding{
		{Tool: "t", Key: "a", Title: "low", Host: "h", Port: 1, Severity: "low", Basis: model.BasisDirect},
		{Tool: "t", Key: "b", Title: "crit", Host: "h", Port: 1, Severity: "critical", CVSS: f64(9.8), Basis: model.BasisDirect},
	}, nil)
	if out[0].Title != "crit" || out[0].Risk.Priority != "P1" {
		t.Errorf("ranking wrong: %+v", out[0].Risk)
	}
}
