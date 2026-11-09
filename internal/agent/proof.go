package agent

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/model"
)

// ProofView is the "show me the proof" record for one finding. It keeps what a tool actually
// observed apart from what code or a model inferred, and it explains the confidence number.
// Everything here is read from stored state; nothing is generated.
type ProofView struct {
	Finding    string         `json:"finding"`
	Title      string         `json:"title"`
	Severity   string         `json:"severity"`
	Status     string         `json:"status"`
	Validation string         `json:"validation"`
	Assets     []string       `json:"assets"`
	Strength   Strength       `json:"strength"`
	Observed   []ObservedItem `json:"observed"`
	Inferred   []InferredItem `json:"inferred"`
	Validated  *Validated     `json:"validated,omitempty"`
	Risk       model.Risk     `json:"risk"`
	Missing    []string       `json:"missing"`
}

// Strength is the evidence-strength score. It is computed by code from how the condition was
// observed and how many independent tools agree. It is NOT a calibrated probability.
type Strength struct {
	Percent  int      `json:"percent"`
	Label    string   `json:"label"`
	Basis    string   `json:"basis"`
	BasisWhy string   `json:"basis_why"`
	Tools    []string `json:"tools"`
	Steps    []string `json:"how_computed"`
	Caveat   string   `json:"caveat"`
}

type ObservedItem struct {
	Evidence string    `json:"evidence"`
	Tool     string    `json:"tool"`
	Asset    string    `json:"asset"`
	Time     time.Time `json:"time"`
	RawRef   string    `json:"raw_ref"`
	RawSHA   string    `json:"raw_sha256,omitempty"`
	Excerpt  string    `json:"excerpt"` // verbatim from the tool output
}

type InferredItem struct {
	Text  string   `json:"text"`
	By    string   `json:"by"` // "rules" (code) or a model name
	Cites []string `json:"cites,omitempty"`
}

const strengthCaveat = "Evidence-strength score computed by code from how the condition was observed and how many independent tools agree. It is not a calibrated probability of being a true positive."

var basisWhy = map[model.Basis]string{
	model.BasisDirect:   "Our own probe observed the vulnerable condition itself (base 0.90).",
	model.BasisReported: "A tool reported it and we did not observe it ourselves (base 0.60).",
	model.BasisVersion:  "Inferred from a product or version string only, with no observation of the flaw (base 0.50).",
}

// Proof returns the proof record for one finding id, or for every finding when id is empty.
func (a *Assessment) Proof(id string) ([]ProofView, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	evByID := map[string]model.Evidence{}
	for _, e := range a.Evidence {
		evByID[e.ID] = e
	}
	stepSHA := map[string]string{}
	for _, s := range a.Steps {
		if s.RawSHA256 != "" {
			stepSHA[s.ID] = s.RawSHA256
		}
	}
	var out []ProofView
	for _, f := range a.Findings {
		if id != "" && f.ID != id {
			continue
		}
		out = append(out, a.proofFor(f, evByID, stepSHA))
	}
	if id != "" && len(out) == 0 {
		return nil, fmt.Errorf("no finding %s", id)
	}
	return out, nil
}

func (a *Assessment) proofFor(f model.Finding, evByID map[string]model.Evidence, stepSHA map[string]string) ProofView {
	pv := ProofView{Finding: f.ID, Title: f.Title, Severity: f.Severity, Status: f.Status, Validation: f.Validation, Risk: f.Risk}
	for _, as := range f.Assets {
		pv.Assets = append(pv.Assets, fmt.Sprintf("%s:%d", as.Host, as.Port))
	}
	for _, eid := range f.Evidence {
		e, ok := evByID[eid]
		if !ok {
			continue
		}
		pv.Observed = append(pv.Observed, ObservedItem{Evidence: e.ID, Tool: e.Tool, Asset: e.Asset, Time: e.Time, RawRef: e.RawRef, RawSHA: stepSHA[e.RunID], Excerpt: e.Excerpt})
	}
	sort.SliceStable(pv.Observed, func(i, j int) bool { return pv.Observed[i].Time.Before(pv.Observed[j].Time) })

	st := Strength{Percent: int(math.Round(f.Confidence * 100)), Label: f.ConfLabel, Basis: string(f.Basis), BasisWhy: basisWhy[f.Basis], Tools: f.Tools, Caveat: strengthCaveat}
	st.Steps = append(st.Steps, "Start from the basis: "+basisWhy[f.Basis])
	if len(f.Tools) > 1 {
		st.Steps = append(st.Steps, fmt.Sprintf("%d independent tools reported it (%s); their scores combine as 1 − Π(1 − c), capped at 0.97.", len(f.Tools), strings.Join(f.Tools, ", ")))
	} else if len(f.Tools) == 1 {
		st.Steps = append(st.Steps, "Reported by one tool ("+f.Tools[0]+"), so there is no cross-tool corroboration.")
	}
	for _, n := range f.Notes {
		if strings.HasPrefix(n, "Triage") || strings.HasPrefix(n, "Corroborated") || strings.HasPrefix(n, "Status") {
			st.Steps = append(st.Steps, n)
		}
	}
	st.Steps = append(st.Steps, fmt.Sprintf("Result: %d%%, labelled %s.", st.Percent, f.ConfLabel))
	pv.Strength = st

	// Inferred = reasoning that is not an observation. Code notes are labelled "rules".
	for _, n := range f.Notes {
		pv.Inferred = append(pv.Inferred, InferredItem{Text: n, By: "rules"})
	}
	for _, in := range f.Inferences {
		pv.Inferred = append(pv.Inferred, InferredItem{Text: in.Text, By: in.By, Cites: in.Cites})
	}
	if v, ok := a.Validations[f.Key]; ok {
		vv := v
		pv.Validated = &vv
	}
	// What this record does NOT establish: stated per finding so the score is not over-read.
	if f.Basis != model.BasisDirect {
		pv.Missing = append(pv.Missing, "No direct observation of the flaw by this assessment.")
	}
	if len(f.Tools) < 2 {
		pv.Missing = append(pv.Missing, "No second independent tool agrees.")
	}
	if f.Validation != "validated" {
		pv.Missing = append(pv.Missing, "Not validated: no approved check has confirmed it.")
	}
	if len(pv.Observed) == 0 {
		pv.Missing = append(pv.Missing, "No stored evidence excerpt is attached.")
	}
	return pv
}
