package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/agent"
	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/pdf"
)

var sevColor = map[string]pdf.RGB{
	"critical": pdf.C(0.55, 0.05, 0.15), "high": pdf.C(0.82, 0.22, 0.12), "medium": pdf.C(0.9, 0.55, 0.1),
	"low": pdf.C(0.2, 0.5, 0.75), "info": pdf.C(0.45, 0.5, 0.55),
}

func ts(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// Build renders the PDF for an assessment. It reads the state under its lock.
func Build(a *agent.Assessment) []byte {
	a.Lock()
	defer a.Unlock()
	entries, auditStatus := a.AuditEntries()
	d := pdf.New("VAPT Report "+a.ID, "AI-assisted VAPT report - "+a.ID+" - CONFIDENTIAL")
	ev := map[string]model.Evidence{}
	for _, e := range a.Evidence {
		ev[e.ID] = e
	}

	// Cover
	d.Space(120)
	d.Para("Vulnerability Assessment & Penetration Test Report", 24, true, pdf.Navy, 0)
	d.Space(6)
	d.Para("AI-assisted, evidence-backed assessment of an authorised lab target", 12, false, pdf.Grey, 0)
	d.Space(40)
	for _, kv := range [][2]string{
		{"Assessment ID", a.ID}, {"Scope", a.Scope.Name}, {"Authorisation reference", a.Scope.Authorization},
		{"Targets", strings.Join(a.Hosts, ", ")}, {"Started", ts(a.Created)}, {"Completed", ts(a.Completed)},
		{"Agent model", a.Model}, {"Classification", "Confidential - client delivery"},
	} {
		d.Para(kv[0]+": "+kv[1], 11, false, pdf.Black, 0)
	}
	d.Space(24)
	d.Para("Reading guide: statements marked OBSERVED come directly from tool output and cite an evidence ID (E-xxxx). Statements marked AI INFERENCE are reasoning about impact, are labelled with the model or rules engine that produced them, and cite the evidence they rest on. Severity, CVSS and CVE data are reproduced from tool output; risk scores are computed by deterministic code from those inputs and the factors shown.", 9.5, false, pdf.Grey, 0)
	d.Break()

	// 7.1
	d.H1("1. Executive Summary")
	d.Para("Assessment scope", 11, true, pdf.Black, 0)
	d.Para(fmt.Sprintf("Authorised targets: %s. Exclusions: %s. Active scanning was %s; offensive validation was %s. All testing stayed inside the organiser-authorised lab scope enforced by a deny-by-default guard.",
		strings.Join(a.Scope.Targets, ", "), orNone(a.Scope.Exclusions), yesNo(a.Scope.AllowActive, "permitted", "not permitted"), yesNo(a.Scope.AllowExploit, "permitted only with per-action human approval", "not permitted")), 10, false, pdf.Black, 0)
	d.Space(4)
	d.Para("Overall assessment ("+label(a.SummaryBy)+")", 11, true, pdf.Black, 0)
	d.Para(a.Summary, 10, false, pdf.Black, 0)
	counts := map[string]int{}
	conf, susp, fp := 0, 0, 0
	for _, f := range a.Findings {
		counts[f.Severity]++
		switch f.Status {
		case "confirmed":
			conf++
		case "likely_false_positive":
			fp++
		default:
			susp++
		}
	}
	d.Space(4)
	d.Para(fmt.Sprintf("Findings: %d total - %d confirmed, %d suspected, %d likely false positive. Evidence items: %d. Tool runs: %d.", len(a.Findings), conf, susp, fp, len(a.Evidence), len(a.Steps)), 10, false, pdf.Black, 0)
	if len(a.Findings) > 0 {
		d.Space(4)
		d.Para("Top priorities", 11, true, pdf.Black, 0)
		for i, f := range a.Findings {
			if i >= 3 {
				break
			}
			d.Para(fmt.Sprintf("%s [%s] %s - %s, %s confidence", f.ID, f.Risk.Priority, f.Title, strings.ToUpper(f.Severity), f.ConfLabel), 10, false, pdf.Black, 10)
		}
	}

	// 7.2
	d.H1("2. Assessment Methodology")
	d.Para("The assessment followed the NIST SP 800-115 technical testing lifecycle (planning, discovery, attack/validation, reporting) with the agent proposing each step, a deterministic scope guard approving or refusing it, and a human analyst approving scans and any active validation. Findings were described using CVE, CVSS and CWE identifiers where tools reported them, and OWASP Top 10 categories for web issues. Use of these references does not establish formal compliance with any standard.", 10, false, pdf.Black, 0)
	d.H2("Rules of engagement")
	for _, s := range []string{
		"Authorisation reference: " + a.Scope.Authorization,
		"Targets: " + strings.Join(a.Scope.Targets, ", ") + "; exclusions: " + orNone(a.Scope.Exclusions),
		fmt.Sprintf("Lab-only addressing enforced: %s", yesNo(!a.Scope.AllowNonLab, "yes (loopback/private ranges only)", "no - organiser override recorded")),
		fmt.Sprintf("Port allow-list: %v; rate limit: %d requests/second (0 = unlimited)", orAny(a.Scope.Ports), a.Scope.MaxReqPerSec),
		"Tools permitted: " + orAnyS(a.Scope.AllowedTools),
		"Exploitation: never autonomous. Validation uses non-exploiting module checks only and requires explicit analyst approval, recorded in the audit trail.",
		"Data handling: raw outputs and the audit log are stored with owner-only permissions; secrets observed in output are redacted in evidence.",
	} {
		d.Para("- "+s, 10, false, pdf.Black, 8)
	}
	d.H2("Assets tested")
	var rows [][]string
	for _, s := range a.Services {
		if s.State == "open" {
			rows = append(rows, []string{fmt.Sprintf("%s:%d/%s", s.Host, s.Port, s.Proto), s.Name, clip(strings.TrimSpace(s.Product+" "+s.Version), 40), s.Tool, s.EvID})
		}
	}
	if len(rows) == 0 {
		d.Para("No open services were recorded.", 10, false, pdf.Grey, 0)
	} else {
		d.Table([]string{"Asset", "Service", "Product / version", "Observed by", "Evidence"}, rows, []float64{120, 70, 160, 80, 65})
	}
	d.H2("Tool execution summary")
	rows = nil
	for _, s := range a.Steps {
		dur := "-"
		if !s.Ended.IsZero() {
			dur = s.Ended.Sub(s.Started).Round(time.Millisecond).String()
		}
		res := s.Status
		if s.Error != "" {
			res += ": " + clip(s.Error, 70)
		} else if s.Summary != "" {
			res += ": " + clip(s.Summary, 60)
		} else if s.Status == "blocked" {
			res += ": " + clip(s.Guard.Reason, 70)
		}
		rows = append(rows, []string{s.ID, s.Tool + " (" + modeShort(s.Mode) + ")", clip(s.Target, 28), res, dur, "by " + shortBy(s.ProposedBy)})
	}
	d.Table([]string{"Step", "Tool (mode)", "Target", "Outcome", "Time", "Planned"}, rows, []float64{36, 85, 100, 160, 55, 59})
	d.H2("Why each step was chosen")
	for _, s := range a.Steps {
		d.Para(fmt.Sprintf("%s %s: %s", s.ID, s.Tool, s.Rationale), 9, false, pdf.Black, 8)
	}

	// 7.3
	d.H1("3. Severity Distribution and Prioritised Findings")
	max := 1
	for _, c := range counts {
		if c > max {
			max = c
		}
	}
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		d.Bar(strings.ToUpper(s[:1])+s[1:], counts[s], max, sevColor[s])
	}
	d.Space(4)
	d.Para("Severity is as reported by the source tool(s) (highest across merged reports). Priority P1-P4 comes from the computed risk score, which combines CVSS (or nominal severity), exposure, tool-reported exploit availability, analyst-set asset criticality and confidence.", 9, false, pdf.Grey, 0)
	d.Space(4)
	rows = nil
	for _, f := range a.Findings {
		cv := "n/r"
		if f.CVSS != nil {
			cv = fmt.Sprintf("%.1f", *f.CVSS)
		}
		rows = append(rows, []string{f.ID, clip(f.Title, 54), clip(assetList(f), 30), strings.ToUpper(f.Severity), cv, fmt.Sprintf("%.0f %s", f.Risk.Score, f.Risk.Priority), f.Status})
	}
	d.Table([]string{"ID", "Finding", "Assets", "Severity", "CVSS", "Risk", "Status"}, rows, []float64{36, 150, 100, 52, 36, 50, 70})

	// 7.4
	d.H1("4. Detailed Vulnerability Findings")
	for _, f := range a.Findings {
		d.Space(6)
		d.Badge(strings.ToUpper(f.Severity), sevColor[f.Severity])
		d.Para(fmt.Sprintf("%s  %s", f.ID, f.Title), 12, true, pdf.Black, 0)
		d.Para("Affected assets (OBSERVED):", 9.5, true, pdf.Grey, 0)
		for _, as := range f.Assets {
			d.Para(fmt.Sprintf("%s:%d %s - reported by %s; evidence %s", as.Host, as.Port, as.Service, strings.Join(as.Tools, ", "), strings.Join(as.Evidence, ", ")), 9.5, false, pdf.Black, 8)
		}
		cv := "not reported by any tool"
		if f.CVSS != nil {
			cv = fmt.Sprintf("%.1f (reported by %s)", *f.CVSS, f.CVSSSource)
			if f.CVSSVector != "" {
				cv += " " + f.CVSSVector
			}
		}
		d.Para(fmt.Sprintf("Severity: %s    CVSS: %s", strings.ToUpper(f.Severity), cv), 9.5, false, pdf.Black, 0)
		d.Para(fmt.Sprintf("CVE: %s    CWE: %s    OWASP: %s", orDash(f.CVEs), orDash(f.CWEs), dash(f.OWASP)), 9.5, false, pdf.Black, 0)
		d.Para(fmt.Sprintf("Status: %s    Confidence: %s (%.0f%%)    Validation: %s    Basis: %s", f.Status, f.ConfLabel, f.Confidence*100, f.Validation, f.Basis), 9.5, true, pdf.Black, 0)
		d.Para("Description (OBSERVED / tool-reported):", 9.5, true, pdf.Grey, 0)
		d.Para(f.Description, 9.5, false, pdf.Black, 8)
		d.Para("Supporting evidence:", 9.5, true, pdf.Grey, 0)
		for _, id := range f.Evidence {
			e := ev[id]
			d.Para(fmt.Sprintf("%s  tool=%s  asset=%s  time=%s", e.ID, e.Tool, e.Asset, ts(e.Time)), 8.5, true, pdf.Black, 8)
			d.Para("raw reference: "+e.RawRef, 8, false, pdf.Grey, 8)
			d.Mono(clip(e.Excerpt, 420), 8, 8)
		}
		if len(f.Notes) > 0 {
			d.Para("Correlation and triage notes (computed by code):", 9.5, true, pdf.Grey, 0)
			for _, n := range f.Notes {
				d.Para("- "+n, 9, false, pdf.Black, 8)
			}
		}
		d.Para("Risk score computation:", 9.5, true, pdf.Grey, 0)
		for _, x := range f.Risk.Factors {
			d.Para(fmt.Sprintf("- %s = %.2f: %s", x.Name, x.Value, x.Source), 8.5, false, pdf.Black, 8)
		}
		d.Para(fmt.Sprintf("=> risk %.1f / 100, priority %s", f.Risk.Score, f.Risk.Priority), 9, true, pdf.Black, 8)
		for _, in := range f.Inferences {
			d.Para(fmt.Sprintf("AI INFERENCE (%s; cites %s):", label(in.By), strings.Join(in.Cites, ", ")), 9.5, true, pdf.C(0.35, 0.2, 0.6), 0)
			d.Para(in.Text, 9.5, false, pdf.Black, 8)
		}
		d.Space(4)
	}

	// 7.5
	d.H1("5. Impact and Remediation")
	for _, f := range a.Findings {
		d.H2(fmt.Sprintf("%s  %s  [%s]", f.ID, f.Title, f.Risk.Priority))
		d.Para("Technical and business impact:", 9.5, true, pdf.Grey, 0)
		if len(f.Inferences) > 0 {
			d.Para(f.Inferences[0].Text+" (AI inference; see Section 4.)", 9.5, false, pdf.Black, 8)
		} else {
			d.Para("No impact inference was produced; see the observed description in Section 4.", 9.5, false, pdf.Black, 8)
		}
		d.Para("Recommended remediation:", 9.5, true, pdf.Grey, 0)
		d.Para(orText(f.Remediation, "No remediation text was supplied by the source tools; consult the references and vendor guidance."), 9.5, false, pdf.Black, 8)
		if len(f.References) > 0 {
			d.Para("References: "+strings.Join(firstS(f.References, 4), "  "), 8.5, false, pdf.Grey, 8)
		}
	}

	// 7.6
	d.H1("6. Assessment Limitations")
	for _, s := range []string{
		"Testing covered only the targets, ports and tools in the registered scope; absence of findings is not proof of absence of vulnerabilities.",
		"Built-in checks are read-only and shallow by design (HTTP configuration, banners, exposure); they do not test authentication, business logic or input handling.",
		"Findings imported from commercial tools (Nessus, Greenbone, Burp) reflect the exports supplied and were not re-run by this agent.",
		"Version-based findings are suspected, not confirmed, until validated; back-ported patches can make them false positives.",
		"Confidence values are calibrated heuristics (basis of detection and corroboration across tools), not statistical probabilities.",
		"LLM output is limited to plans and impact reasoning; it cannot set severity, CVSS, CVE data or risk scores, and ungrounded statements are rejected by code.",
	} {
		d.Para("- "+s, 9.5, false, pdf.Black, 8)
	}
	d.H2("Assumptions")
	d.Para("- The targets are organiser-provided lab systems and were not modified during the test.\n- Tool outputs were taken as produced; timestamps are in UTC from the agent host clock.", 9.5, false, pdf.Black, 8)
	d.H2("Scan failures, skipped and blocked steps")
	any := false
	for _, s := range a.Steps {
		if s.Status == "failed" || s.Status == "skipped" || s.Status == "blocked" || s.Status == "declined" {
			any = true
			d.Para(fmt.Sprintf("%s %s on %s - %s: %s", s.ID, s.Tool, s.Target, s.Status, orText(s.Error, s.Guard.Reason)), 9.5, false, pdf.Black, 8)
		}
	}
	for _, l := range a.Limitations {
		any = true
		d.Para("- "+l, 9.5, false, pdf.Black, 8)
	}
	if !any {
		d.Para("No tool failures, skips or scope refusals occurred.", 9.5, false, pdf.Black, 8)
	}
	d.H2("Human approvals")
	if len(a.Approvals) == 0 {
		d.Para("No active validation was requested; no offensive validation was performed.", 9.5, false, pdf.Black, 8)
	}
	for _, ap := range a.Approvals {
		d.Para(fmt.Sprintf("%s for %s (%s on %s): %s by %s at %s. Reason: %s. Outcome: %s", ap.ID, ap.FindingID, ap.Module, ap.Target, ap.Status, orText(ap.Analyst, "-"), ts(ap.Decided), orText(ap.Reason, "-"), orText(ap.Outcome, "-")), 9.5, false, pdf.Black, 8)
	}
	var planApprovals []string
	for _, e := range entries {
		if e.Type == "approval" && strings.HasPrefix(e.Actor, "analyst:") && e.Detail["step"] != "" {
			planApprovals = append(planApprovals, fmt.Sprintf("%s %s %s", ts(e.Time), e.Actor, e.Summary))
		}
	}
	if len(planApprovals) > 0 {
		d.Para("Plan approvals:", 9.5, true, pdf.Grey, 0)
		for _, p := range planApprovals {
			d.Para("- "+p, 8.5, false, pdf.Black, 8)
		}
	}
	d.H2("Assessment timestamps")
	d.Para(fmt.Sprintf("Started %s; analysis completed %s; report generated %s.", ts(a.Created), ts(a.Completed), ts(time.Now())), 9.5, false, pdf.Black, 8)

	// Appendices
	d.H1("Appendix A. Integration status")
	var mrows [][]string
	for _, m := range Matrix(a.Registry()) {
		av := "yes"
		if !m.Available {
			av = "no: " + clip(m.Note, 40)
		}
		mrows = append(mrows, []string{m.Tool, m.Status, av, clip(m.Limitations, 230)})
	}
	d.Table([]string{"Tool", "Status", "Available here", "Limitations"}, mrows, []float64{80, 82, 95, 238})
	d.H1("Appendix B. Evidence index")
	rows = nil
	for _, e := range a.Evidence {
		rows = append(rows, []string{e.ID, e.Tool, clip(e.Asset, 22), ts(e.Time), clip(e.RawRef, 60)})
	}
	d.Table([]string{"ID", "Tool", "Asset", "Time", "Raw reference"}, rows, []float64{44, 52, 90, 120, 189})
	d.H1("Appendix C. Decision and audit trace")
	d.Para(fmt.Sprintf("Hash-chained audit log: %d entries, integrity %s. Head hash %s.", len(entries), auditStatus, headHash(entries)), 9, false, pdf.Black, 0)
	d.Space(3)
	for _, e := range entries {
		d.Para(fmt.Sprintf("#%d %s %s %s: %s", e.Seq, e.Time.UTC().Format("15:04:05"), e.Actor, e.Type, clip(e.Summary, 170)), 7.5, false, pdf.Black, 0)
	}
	return d.Bytes()
}
