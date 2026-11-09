package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/llm"
	"github.com/ayanasarkar/vapt-agent/internal/model"
)

// ChatResult is one agent reply plus how it was produced, so the UI can label it honestly.
type ChatResult struct {
	Reply    string   `json:"reply"`
	Source   string   `json:"source"`             // "model" (verified) | "rules"
	Model    string   `json:"model,omitempty"`    // set when Source is "model"
	Verified []string `json:"verified,omitempty"` // every F-/E-/S-/CVE reference the reply used, all checked against state
	Rejected string   `json:"rejected,omitempty"` // why a model answer was discarded, if it was
	Suggest  []string `json:"suggest,omitempty"`  // proposed next steps; text only, nothing is executed from them
	DataLeft bool     `json:"data_left_machine"`  // true when this reply sent assessment data to a remote model
}

const chatSystem = `You are KAVACH, an assistant inside an authorised penetration-test console. You explain the assessment to the analyst.
RULES
- Answer ONLY from CONTEXT. If the answer is not in CONTEXT, say you do not have that evidence.
- Refer to things by their IDs in square brackets, for example [F-001], [E-0004], [S-02]. Never invent an ID, CVE, score, port or version.
- Keep OBSERVED (what a tool output shows) separate from INFERRED (your reasoning). Say which is which.
- Confidence numbers in CONTEXT are evidence-strength scores computed by code, not probabilities. Never present them as probabilities.
- You cannot run tools or approve anything. Active validation only happens when the analyst requests it and approves it.
- Never suggest testing anything outside the scope listed in CONTEXT.
- Be brief and concrete. No markdown headings.
Reply with ONE JSON object only: {"reply":"...","suggest":["optional next step the analyst could take","..."]}`

var (
	idRe  = regexp.MustCompile(`\b(?:F-\d{3}|E-\d{4}|S-\d{2})\b`)
	cveRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
)

// groundingContext is what the model is allowed to know. It is built from stored state only.
func (a *Assessment) groundingContext() (string, map[string]bool) {
	allowed := map[string]bool{}
	type ev struct {
		ID, Tool, Asset, Excerpt string
	}
	fs := append([]model.Finding(nil), a.Findings...)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Risk.Score > fs[j].Risk.Score })
	if len(fs) > 25 {
		fs = fs[:25]
	}
	evByID := map[string]model.Evidence{}
	for _, e := range a.Evidence {
		evByID[e.ID] = e
	}
	var findings []map[string]any
	var evs []ev
	seen := map[string]bool{}
	for _, f := range fs {
		allowed[f.ID] = true
		for _, c := range f.CVEs {
			allowed[strings.ToUpper(c)] = true
		}
		var assets []string
		for _, as := range f.Assets {
			assets = append(assets, fmt.Sprintf("%s:%d", as.Host, as.Port))
		}
		findings = append(findings, map[string]any{
			"id": f.ID, "title": f.Title, "severity": f.Severity, "status": f.Status, "validation": f.Validation,
			"evidence_strength_pct": int(f.Confidence*100 + 0.5), "basis": f.Basis, "tools": f.Tools, "assets": assets,
			"cves": f.CVEs, "cwes": f.CWEs, "risk_score": f.Risk.Score, "priority": f.Risk.Priority, "notes": f.Notes, "evidence": f.Evidence,
		})
		for _, id := range f.Evidence {
			if e, ok := evByID[id]; ok && !seen[id] && len(evs) < 60 {
				seen[id] = true
				x := e.Excerpt
				if len(x) > 280 {
					x = x[:280] + "…"
				}
				evs = append(evs, ev{e.ID, e.Tool, e.Asset, x})
				allowed[e.ID] = true
			}
		}
	}
	var steps []map[string]any
	for _, s := range a.Steps {
		allowed[s.ID] = true
		steps = append(steps, map[string]any{"id": s.ID, "tool": s.Tool, "target": s.Target, "status": s.Status, "rationale": s.Rationale, "proposed_by": s.ProposedBy, "guard": s.Guard.Reason})
	}
	var evOut []map[string]string
	for _, e := range evs {
		evOut = append(evOut, map[string]string{"id": e.ID, "tool": e.Tool, "asset": e.Asset, "excerpt": e.Excerpt})
	}
	b, _ := json.Marshal(map[string]any{
		"analyst_request": a.Request, "phase": a.Phase, "round": a.Round,
		"scope": map[string]any{"targets": a.Scope.Targets, "exclusions": a.Scope.Exclusions, "active_scanning_allowed": a.Scope.AllowActive},
		"steps": steps, "findings": findings, "evidence": evOut, "limitations": a.Limitations})
	return string(b), allowed
}

// verifyReply checks every identifier the model used. It returns the verified list, or an error
// naming the first thing that is not in this assessment.
func verifyReply(text string, allowed map[string]bool, userMsg string) ([]string, error) {
	userCVE := map[string]bool{}
	for _, c := range cveRe.FindAllString(userMsg, -1) {
		userCVE[strings.ToUpper(c)] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, id := range idRe.FindAllString(text, -1) {
		if !allowed[id] {
			return nil, fmt.Errorf("the model cited %s, which is not in this assessment", id)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, c := range cveRe.FindAllString(text, -1) {
		c = strings.ToUpper(c)
		if !allowed[c] && !userCVE[c] {
			return nil, fmt.Errorf("the model named %s, which no tool in this assessment reported", c)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// modelAnswer asks the configured model and returns a verified result, or an error meaning "use the rules reply".
func (a *Assessment) modelAnswer(ctx context.Context, msg, ctxJSON string, allowed map[string]bool) (*ChatResult, error) {
	if _, none := a.llm.(llm.None); none {
		return nil, llm.ErrNoModel
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	user, _ := json.Marshal(map[string]string{"CONTEXT": ctxJSON, "ANALYST_QUESTION": msg})
	raw, err := a.llm.Complete(cctx, chatSystem, string(user))
	if err != nil {
		return nil, err
	}
	js, err := llm.ExtractJSON(raw)
	if err != nil {
		return nil, err
	}
	var p struct {
		Reply   string   `json:"reply"`
		Suggest []string `json:"suggest"`
	}
	if err := json.Unmarshal([]byte(js), &p); err != nil || strings.TrimSpace(p.Reply) == "" {
		return nil, fmt.Errorf("model reply was not the expected JSON")
	}
	if len(p.Reply) > 3000 {
		p.Reply = p.Reply[:3000] + "…"
	}
	ver, err := verifyReply(p.Reply, allowed, msg)
	if err != nil {
		return nil, err
	}
	res := &ChatResult{Reply: strings.TrimSpace(p.Reply), Source: "model", Model: a.llm.Name(), Verified: ver, DataLeft: llm.DataLeaves(a.llm)}
	for _, s := range p.Suggest {
		if len(res.Suggest) == 3 {
			break
		}
		if s = strings.TrimSpace(s); s != "" && len(s) <= 200 {
			if _, e := verifyReply(s, allowed, msg); e == nil {
				res.Suggest = append(res.Suggest, s)
			}
		}
	}
	return res, nil
}
