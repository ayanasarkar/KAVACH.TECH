package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/adapters"
	"github.com/ayanasarkar/vapt-agent/internal/llm"
	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

type fakeLLM struct {
	reply string
	err   error
}

func (f fakeLLM) Name() string { return "fake" }
func (f fakeLLM) Complete(context.Context, string, string) (string, error) {
	return f.reply, f.err
}

func newA(t *testing.T, c llm.Client, sc scope.Scope, hosts []string, req string, auto bool) *Assessment {
	t.Helper()
	if sc.Authorization == "" {
		sc.Authorization = "T"
	}
	a, err := New(Env{DataDir: t.TempDir(), Reg: adapters.NewRegistry(), LLM: c}, "t1", req, sc, hosts, nil, auto)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func wait(t *testing.T, a *Assessment, phases ...string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		a.Lock()
		p := a.Phase
		a.Unlock()
		for _, w := range phases {
			if p == w {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %v (phase %s)", phases, a.Phase)
}

func TestRequestMentioningOutOfScopeHostIsRefusedAndAudited(t *testing.T) {
	a := newA(t, llm.None{}, scope.Scope{Targets: []string{"127.0.0.0/30"}, AllowActive: true}, []string{"127.0.0.1"}, "scan 127.0.0.1 and also 8.8.8.8 and 10.1.1.1", false)
	a.Lock()
	added, refused := a.ingestRequest(a.Request)
	a.Unlock()
	if len(refused) != 2 {
		t.Fatalf("refused=%v added=%v", refused, added)
	}
	es, st := a.AuditEntries()
	if st != "verified" {
		t.Fatal(st)
	}
	n := 0
	for _, e := range es {
		if e.Type == "scope_decision" && e.Detail["allowed"] == "false" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("want 2 audited refusals, got %d", n)
	}
}

func TestModelCannotSmuggleMetasploitOrOutOfScopeTargets(t *testing.T) {
	plan := `{"reasoning":"go","steps":[
	  {"tool":"metasploit","target":"127.0.0.1","options":{"module":"exploit/x/y"},"rationale":"just do it"},
	  {"tool":"nmap","target":"8.8.8.8","rationale":"also this"},
	  {"tool":"rm","target":"127.0.0.1","rationale":"bogus tool"},
	  {"tool":"portscan","target":"127.0.0.1","options":{"ports":"1"},"rationale":"legit"}]}`
	a := newA(t, fakeLLM{reply: "text before " + plan + " after"}, scope.Scope{Targets: []string{"127.0.0.1"}, AllowActive: true, AllowExploit: true}, []string{"127.0.0.1"}, "x", false)
	a.planRound(context.Background())
	got := map[string]string{}
	for _, s := range a.Steps {
		got[s.Tool+"|"+s.Target] = s.Status
	}
	if got["metasploit|127.0.0.1"] != "blocked" {
		t.Errorf("model-proposed metasploit not blocked: %v", got)
	}
	if got["nmap|8.8.8.8"] != "blocked" {
		t.Errorf("out-of-scope target not blocked: %v", got)
	}
	if got["rm|127.0.0.1"] != "blocked" {
		t.Errorf("unknown tool not blocked: %v", got)
	}
	if got["portscan|127.0.0.1"] != "proposed" {
		t.Errorf("legit step not proposed: %v", got)
	}
}

func TestBadModelOutputFallsBackToRules(t *testing.T) {
	for name, c := range map[string]llm.Client{"garbage": fakeLLM{reply: "not json"}, "error": fakeLLM{err: errors.New("503")}} {
		a := newA(t, c, scope.Scope{Targets: []string{"127.0.0.1"}, AllowActive: true}, []string{"127.0.0.1"}, "x", false)
		n := a.planRound(context.Background())
		if n == 0 {
			t.Errorf("%s: no fallback plan", name)
		}
		if a.Steps[0].ProposedBy != "rules" {
			t.Errorf("%s: proposed by %s", name, a.Steps[0].ProposedBy)
		}
	}
}

func TestPlanDoesNotRepeatDoneSteps(t *testing.T) {
	a := newA(t, llm.None{}, scope.Scope{Targets: []string{"127.0.0.1"}, AllowActive: true}, []string{"127.0.0.1"}, "x", false)
	if a.planRound(context.Background()) == 0 {
		t.Fatal("no steps")
	}
	if n := a.planRound(context.Background()); n != 0 {
		t.Errorf("repeated %d steps already planned", n)
	}
}

func TestPassiveOnlyScopeProposesNoActiveScans(t *testing.T) {
	a := newA(t, llm.None{}, scope.Scope{Targets: []string{"127.0.0.1"}, AllowActive: false}, []string{"127.0.0.1"}, "x", false)
	a.planRound(context.Background())
	for _, s := range a.Steps {
		if s.Kind == scope.KindActive {
			t.Errorf("active step %s proposed without authorisation", s.Tool)
		}
	}
}

func TestInferenceGroundingRejectsFabrication(t *testing.T) {
	cvss := 7.5
	f := &model.Finding{ID: "F-001", Evidence: []string{"E-1"}, CVEs: []string{"CVE-2021-1111"}, CVSS: &cvss}
	ev := map[string]model.Evidence{"E-1": {ID: "E-1", Excerpt: "banner mentions CVE-2021-1111"}}
	ok := func(text string, cites ...string) bool { return inferenceOK(text, cites, f, ev) }
	if !ok("This may allow remote access.", "E-1") {
		t.Error("valid inference rejected")
	}
	if ok("This may allow remote access.") {
		t.Error("uncited inference accepted")
	}
	if ok("This may allow remote access.", "E-99") {
		t.Error("citation of foreign evidence accepted")
	}
	if ok("Exploits CVE-2099-0001 to take over.", "E-1") {
		t.Error("fabricated CVE accepted")
	}
	if !ok("Relates to CVE-2021-1111.", "E-1") {
		t.Error("real CVE rejected")
	}
	if ok("CVSS 9.9 critical.", "E-1") || !ok("CVSS 7.5 per the tool.", "E-1") {
		t.Error("CVSS number grounding wrong")
	}
	if summaryOK("See [F-009] and CVE-2000-1.", []model.Finding{*f}) {
		t.Error("summary with unknown finding/CVE accepted")
	}
}

func TestEndToEndAgainstLocalWebServerWithApprovalGate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Server", "T/1.0")
			fmt.Fprint(w, "<html><title>x</title></html>")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	a := newA(t, llm.None{}, scope.Scope{Targets: []string{"127.0.0.1"}, AllowActive: true, AllowExploit: true}, []string{srv.URL}, "check "+srv.URL, false)
	a.Start()
	wait(t, a, "awaiting_approval")
	// Nothing may have run before approval.
	a.Lock()
	for _, s := range a.Steps {
		if s.Status == "running" || s.Status == "done" {
			t.Errorf("%s ran before approval", s.ID)
		}
	}
	a.Unlock()
	if err := a.ApprovePlan(nil, "tester"); err != nil {
		t.Fatal(err)
	}
	wait(t, a, "review")
	a.Lock()
	if len(a.Findings) == 0 || len(a.Evidence) == 0 {
		t.Fatalf("no findings/evidence: %d/%d", len(a.Findings), len(a.Evidence))
	}
	fid := a.Findings[0].ID
	a.Unlock()

	// Validation: requested != executed; approval needs reason + typed target.
	ap, err := a.RequestValidation(fid, "auxiliary/scanner/http/title", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Decide(ap.ID, true, "tester", "", "127.0.0.1"); err == nil {
		t.Error("approval without a reason accepted")
	}
	if err := a.Decide(ap.ID, true, "tester", "lab check", "wrong"); err == nil {
		t.Error("approval without target confirmation accepted")
	}
	if err := a.Decide(ap.ID, true, "tester", "lab check", ap.Target); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	a.Lock()
	var st *Step
	for i := range a.Steps {
		if a.Steps[i].Tool == "metasploit" {
			st = &a.Steps[i]
		}
	}
	a.Unlock()
	if st == nil || (st.Status != "failed" && st.Status != "done") {
		t.Fatalf("validation step state: %+v", st)
	}
	if st.Status == "failed" && !strings.Contains(st.Error, "not installed") {
		t.Errorf("unexpected failure: %s", st.Error)
	}
	es, status := a.AuditEntries()
	if status != "verified" {
		t.Fatal(status)
	}
	var sawReq, sawApproval bool
	for _, e := range es {
		sawReq = sawReq || e.Type == "approval_requested"
		sawApproval = sawApproval || (e.Type == "approval" && strings.Contains(e.Summary, "approved"))
	}
	if !sawReq || !sawApproval {
		t.Error("approval request/decision missing from audit trail")
	}
}

func TestValidationRefusedWhenScopeForbidsIt(t *testing.T) {
	a := newA(t, llm.None{}, scope.Scope{Targets: []string{"127.0.0.1"}, AllowActive: true, AllowExploit: false}, []string{"127.0.0.1"}, "x", false)
	a.Lock()
	a.Findings = []model.Finding{{ID: "F-001", Key: "k", Assets: []model.Affected{{Host: "127.0.0.1", Port: 80}}}}
	a.Unlock()
	if _, err := a.RequestValidation("F-001", "auxiliary/scanner/http/title", "t"); err == nil {
		t.Fatal("validation requested although scope forbids offensive validation")
	}
}

func TestDenyPlanRunsNothingAndIsAudited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<html></html>") }))
	defer srv.Close()
	a := newA(t, llm.None{}, scope.Scope{Targets: []string{"127.0.0.1"}, AllowActive: true}, []string{srv.URL}, "check "+srv.URL, false)
	a.Start()
	wait(t, a, "awaiting_approval")
	if err := a.DenyPlan("tester", "not today"); err != nil {
		t.Fatal(err)
	}
	wait(t, a, "review")
	a.Lock()
	for _, s := range a.Steps {
		if s.Status != "declined" {
			t.Errorf("%s is %s, want declined", s.ID, s.Status)
		}
	}
	if len(a.Evidence) != 0 {
		t.Errorf("a denied plan produced %d evidence items", len(a.Evidence))
	}
	a.Unlock()
	if err := a.DenyPlan("tester", ""); err == nil {
		t.Error("second deny should fail: no plan is waiting")
	}
	if _, st := a.AuditEntries(); st != "verified" {
		t.Errorf("audit chain status after deny: %s", st)
	}
}
