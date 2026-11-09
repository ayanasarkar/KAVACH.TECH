package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/llm"
	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// seed puts one directly-observed finding and its evidence into an assessment, without running any tool.
func seed(t *testing.T, c llm.Client) *Assessment {
	t.Helper()
	a := newA(t, c, scope.Scope{Targets: []string{"127.0.0.0/30"}, AllowActive: true}, []string{"127.0.0.1"}, "check 127.0.0.1", false)
	a.Lock()
	a.Evidence = []model.Evidence{{ID: "E-0001", Tool: "webcheck", Asset: "127.0.0.1:8081", Time: time.Now().UTC(), RawRef: "run-1/webcheck.txt#L3", Excerpt: "no X-Frame-Options header", RunID: "S-01"}}
	a.Steps = append(a.Steps, Step{ID: "S-01", Tool: "webcheck", Target: "127.0.0.1", Rationale: "HTTP port seen open", Status: "done", RawSHA256: "abc123"})
	a.Findings = []model.Finding{{ID: "F-001", Title: "Missing clickjacking protection", Severity: "low", Status: "confirmed", Validation: "not_validated",
		Basis: model.BasisDirect, Confidence: 0.9, ConfLabel: "high", Tools: []string{"webcheck"}, Evidence: []string{"E-0001"}, CVEs: []string{"CVE-2020-1234"},
		Assets: []model.Affected{{Host: "127.0.0.1", Port: 8081}}, Notes: []string{"Triage: header absent in response."}}}
	a.Unlock()
	return a
}

func auditHas(a *Assessment, typ string) bool {
	es, _ := a.AuditEntries()
	for _, e := range es {
		if e.Type == typ {
			return true
		}
	}
	return false
}

func TestChatAcceptsGroundedModelAnswer(t *testing.T) {
	a := seed(t, fakeLLM{reply: `{"reply":"Observed: [E-0001] shows no X-Frame-Options on the web port. Inferred: pages could be framed. See [F-001] and CVE-2020-1234.","suggest":["Review the header policy on [S-01]'s target"]}`})
	r := a.ChatDetailed(context.Background(), "what is F-001?")
	if r.Source != "model" || r.Rejected != "" {
		t.Fatalf("want accepted model answer, got %+v", r)
	}
	if len(r.Verified) != 3 || len(r.Suggest) != 1 {
		t.Fatalf("verified=%v suggest=%v", r.Verified, r.Suggest)
	}
	if !auditHas(a, "chat_reply") {
		t.Error("acceptance not audited")
	}
}

func TestChatRejectsInventedFindingID(t *testing.T) {
	a := seed(t, fakeLLM{reply: `{"reply":"[F-999] is critical and exploitable."}`})
	r := a.ChatDetailed(context.Background(), "anything critical?")
	if r.Source != "rules" || !strings.Contains(r.Rejected, "F-999") {
		t.Fatalf("fabricated ID must fall back to rules: %+v", r)
	}
	if strings.Contains(r.Reply, "F-999") {
		t.Error("fabricated text leaked into the reply")
	}
	if !auditHas(a, "chat_rejected") {
		t.Error("rejection not audited")
	}
}

func TestChatRejectsInventedCVEAndEvidence(t *testing.T) {
	for _, reply := range []string{
		`{"reply":"This maps to CVE-2099-99999."}`,
		`{"reply":"Proof is in [E-0777]."}`,
		`{"reply":"Run [S-77] again."}`,
	} {
		a := seed(t, fakeLLM{reply: reply})
		if r := a.ChatDetailed(context.Background(), "tell me more"); r.Source != "rules" || r.Rejected == "" {
			t.Errorf("%s -> %+v", reply, r)
		}
	}
}

func TestChatAllowsCVEOnlyIfAnalystRaisedIt(t *testing.T) {
	a := seed(t, fakeLLM{reply: `{"reply":"CVE-2021-41773 is not reported by any tool in this assessment."}`})
	if r := a.ChatDetailed(context.Background(), "is CVE-2021-41773 relevant?"); r.Source != "model" {
		t.Fatalf("echoing the analyst's own CVE with a 'not found' answer should pass: %+v", r)
	}
}

func TestChatFallsBackWhenModelFailsOrIsAbsent(t *testing.T) {
	for _, c := range []llm.Client{fakeLLM{err: context.DeadlineExceeded}, fakeLLM{reply: "not json"}, llm.None{}} {
		a := seed(t, c)
		r := a.ChatDetailed(context.Background(), "explain F-001")
		if r.Source != "rules" || !strings.Contains(r.Reply, "F-001") {
			t.Errorf("%s: %+v", c.Name(), r)
		}
	}
}

func TestChatScopeDecisionIsCodeNotModel(t *testing.T) {
	a := seed(t, fakeLLM{reply: `{"reply":"Sure, I scanned 8.8.8.8 for you."}`})
	r := a.ChatDetailed(context.Background(), "also scan 8.8.8.8")
	if !strings.HasPrefix(r.Reply, "I refused these targets") {
		t.Fatalf("code's refusal must come first: %q", r.Reply)
	}
	if !auditHas(a, "scope_decision") {
		t.Error("refusal not audited")
	}
}

func TestChatTurnRecordsSource(t *testing.T) {
	a := seed(t, llm.None{})
	a.ChatDetailed(context.Background(), "explain F-001")
	a.Lock()
	defer a.Unlock()
	last := a.Messages[len(a.Messages)-1]
	if last.Role != "agent" || last.Source != "rules" {
		t.Fatalf("%+v", last)
	}
}

func TestProofSeparatesObservedFromInferredAndLabelsScore(t *testing.T) {
	a := seed(t, llm.None{})
	pv, err := a.Proof("F-001")
	if err != nil || len(pv) != 1 {
		t.Fatal(err, pv)
	}
	p := pv[0]
	if p.Strength.Percent != 90 || !strings.Contains(p.Strength.Caveat, "not a calibrated probability") {
		t.Errorf("strength=%+v", p.Strength)
	}
	if len(p.Observed) != 1 || p.Observed[0].Excerpt != "no X-Frame-Options header" || p.Observed[0].RawSHA != "abc123" {
		t.Errorf("observed=%+v", p.Observed)
	}
	if len(p.Inferred) != 1 || p.Inferred[0].By != "rules" {
		t.Errorf("inferred=%+v", p.Inferred)
	}
	joined := strings.Join(p.Missing, "|")
	if !strings.Contains(joined, "Not validated") || !strings.Contains(joined, "second independent tool") {
		t.Errorf("missing=%v", p.Missing)
	}
	if _, err := a.Proof("F-404"); err == nil {
		t.Error("unknown finding should error")
	}
}
