package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/adapters"
	"github.com/ayanasarkar/vapt-agent/internal/agent"
	"github.com/ayanasarkar/vapt-agent/internal/audit"
	"github.com/ayanasarkar/vapt-agent/internal/llm"
	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// pdfStrings returns every text string drawn on the PDF, in order, unescaped. Streams are uncompressed.
func pdfStrings(b []byte) []string {
	re := regexp.MustCompile(`(?m)Td \((.*)\) Tj ET$`)
	un := strings.NewReplacer(`\(`, "(", `\)`, ")", `\\`, `\`)
	var out []string
	for _, m := range re.FindAllSubmatch(b, -1) {
		out = append(out, un.Replace(string(m[1])))
	}
	return out
}

const host = "www.hackthecore.in"

// fixtureAssessment reproduces the shape of the judged run: one host on :22/:80/:443/:8000, a finding that merged
// three ports, a finding with a long title, and a TLS port whose nmap label said "http" while webcheck negotiated TLS.
func fixtureAssessment(t *testing.T) (*agent.Assessment, map[string]string) {
	t.Helper()
	a, err := agent.New(agent.Env{DataDir: t.TempDir(), Reg: adapters.NewRegistry(), LLM: llm.None{}}, "20261120-205114-501d", "assess "+host,
		scope.Scope{Name: "Local lab - " + host, Authorization: "HACKATHON-LAB-001", Targets: []string{"127.0.0.0/30"}, AllowActive: true}, []string{host}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	raws := map[string]string{}
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	now := time.Now().UTC()
	a.Lock()
	defer a.Unlock()
	for _, st := range []struct{ id, tool, target, body string }{
		{"S-01", "nmap", host, "22/tcp open ssh\n80/tcp open http\n"},
		{"S-02", "webcheck", "http://" + host, "GET / -> 200\n"},
		{"S-03", "webcheck", "https://" + host + ":443", "GET / -> 200\n"},
		{"S-04", "webcheck", "http://" + host + ":8000", "GET / -> 200\n"},
	} {
		raws[st.id] = sum(st.body)
		a.Steps = append(a.Steps, agent.Step{ID: st.id, Tool: st.tool, Target: st.target, Status: "done", Mode: "live", Summary: st.target + " -> HTTP 200, 4 issues",
			ProposedBy: "llm:test", RawFile: "raw/" + st.id + "-" + st.tool + ".txt", RawSHA256: raws[st.id], Started: now, Ended: now.Add(time.Second)})
	}
	for _, p := range []struct {
		port int
		name string
		tool string
	}{{22, "ssh", "nmap"}, {80, "http", "nmap"}, {443, "https", "nmap"}, {8000, "http-alt", "nmap"}} {
		a.Services = append(a.Services, model.Service{Host: host, Port: p.port, Proto: "tcp", State: "open", Name: p.name, Tool: p.tool, Product: "nginx", Version: "1.24.0", EvID: "E-1"})
	}
	assets := []model.Affected{{Host: host, Port: 80, Service: "http", Evidence: []string{"E-0002"}, Tools: []string{"webcheck"}},
		{Host: host, Port: 443, Service: "https", Evidence: []string{"E-0003"}, Tools: []string{"webcheck"}},
		{Host: host, Port: 8000, Service: "http-alt", Evidence: []string{"E-0004"}, Tools: []string{"webcheck"}}}
	a.Findings = []model.Finding{
		{ID: "F-001", Key: "web:exposed-git", Title: "Exposed .git repository metadata", Severity: "high", Status: "confirmed", Assets: assets, CWEs: []string{"CWE-527"}, Evidence: []string{"E-0002"}, Tools: []string{"webcheck"}, Description: "d"},
		{ID: "F-002", Key: "web:missing-header:x-frame-options", Title: "Missing clickjacking protection (X-Frame-Options / frame-ancestors)", Severity: "low", Status: "confirmed", Assets: assets, CWEs: []string{"CWE-1021"}, Evidence: []string{"E-0003"}, Tools: []string{"webcheck"}, Description: "d"},
	}
	for _, e := range []model.Evidence{{ID: "E-0002", Tool: "webcheck", Asset: host + ":80"}, {ID: "E-0003", Tool: "webcheck", Asset: host + ":443"}, {ID: "E-0004", Tool: "webcheck", Asset: host + ":8000"}} {
		e.Time, e.RawRef = now, "raw/S-02-webcheck.txt - line 10"
		a.Evidence = append(a.Evidence, e)
	}
	return a, raws
}

func TestAssetSummaryGroupsPortsUnderOneHost(t *testing.T) {
	f := model.Finding{Assets: []model.Affected{{Host: host, Port: 80}, {Host: host, Port: 443}, {Host: host, Port: 8000}}}
	if got, want := assetSummary(f), host+" (:80, :443, :8000)"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if got, want := assetCell(f), host+"\n(:80, :443, :8000)"; got != want {
		t.Errorf("cell: got %q want %q", got, want)
	}
	f.Assets = []model.Affected{{Host: "a.example", Port: 22}, {Host: "b.example", Port: 80}, {Host: "c.example"}}
	if got, want := assetSummary(f), "a.example (:22); b.example (:80); c.example"; got != want {
		t.Errorf("multi-host: got %q want %q", got, want)
	}
}

func TestOutcomeTextDropsOnlyTheRepeatedTarget(t *testing.T) {
	if got := outcomeText("http://h:8000 -> HTTP 200, 4 issues", "http://h:8000"); got != "HTTP 200, 4 issues" {
		t.Errorf("repeat not dropped: %q", got)
	}
	// after a protocol fallback the summary URL differs from the target; that URL must stay visible
	in := "https://h:9000 -> HTTP 200, 4 issues (scheme corrected by protocol fallback)"
	if got := outcomeText(in, "h:9000"); got != in {
		t.Errorf("corrected URL was hidden: %q", got)
	}
	if got := outcomeText("nmap: 4 open ports", "h"); got != "nmap: 4 open ports" {
		t.Errorf("summary without a URL changed: %q", got)
	}
}

// between returns the drawn strings between two headings.
func between(t *testing.T, ss []string, from, to string) []string {
	t.Helper()
	lo, hi := -1, len(ss)
	for i, s := range ss {
		if lo < 0 && s == from {
			lo = i
		} else if lo >= 0 && s == to {
			hi = i
			break
		}
	}
	if lo < 0 {
		t.Fatalf("heading %q not found in the PDF", from)
	}
	return ss[lo:hi]
}

func contains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// The judged 501d report cut ":8000" off in three tables. Every port must survive into the rendered PDF, in the
// section where it used to be lost, and nothing there may end in the "..." that clip() draws (\205 in WinAnsi).
func TestBuildKeepsEveryPortAndFullTitleVisible(t *testing.T) {
	a, _ := fixtureAssessment(t)
	b := Build(a)
	if len(b) == 0 || !strings.HasPrefix(string(b), "%PDF") {
		t.Fatal("no PDF produced")
	}
	if p := os.Getenv("KAVACH_TEST_PDF_OUT"); p != "" {
		os.WriteFile(p, b, 0o644)
	}
	ss := pdfStrings(b)

	sec2 := between(t, ss, "Assets tested", "Why each step was chosen") // assets table + tool execution summary
	for _, want := range []string{host + ":8000/tcp", "https://" + host + ":443"} {
		if !contains(sec2, want) {
			t.Errorf("section 2 tables lost %q", want)
		}
	}

	sec3 := between(t, ss, "3. Severity Distribution and Prioritised Findings", "4. Detailed Vulnerability Findings")
	if !contains(sec3, "(:80, :443, :8000)") {
		t.Errorf("section 3 findings table does not show every port grouped under the host: %q", sec3)
	}
	if !contains(sec3, "frame-ancestors)") {
		t.Error("section 3 findings table cut the long title short")
	}

	appB := between(t, ss, "Appendix B. Evidence index", "Appendix C. Decision and audit trace")
	for _, port := range []string{":80", ":443", ":8000"} {
		found := false
		for _, s := range appB {
			if s == host+port {
				found = true
			}
		}
		if !found {
			t.Errorf("Appendix B evidence index lost the full asset %s%s", host, port)
		}
	}

	for name, sec := range map[string][]string{"section 2": sec2, "section 3": sec3, "Appendix B": appB} {
		for _, s := range sec {
			if strings.Contains(s, `\205`) {
				t.Errorf("%s draws a clipped (ellipsis) string: %q", name, s)
			}
		}
	}
}

func TestBuildAppendixCListsSealedRawDigestsAndHowToVerify(t *testing.T) {
	a, raws := fixtureAssessment(t)
	all := strings.Join(pdfStrings(Build(a)), "\n")
	files := map[string]string{"S-01": "raw/S-01-nmap.txt", "S-02": "raw/S-02-webcheck.txt", "S-03": "raw/S-03-webcheck.txt", "S-04": "raw/S-04-webcheck.txt"}
	for step, sum := range raws {
		if !strings.Contains(all, files[step]+": "+sum) {
			t.Errorf("Appendix C is missing the digest line for %s", files[step])
		}
	}
	if !strings.Contains(all, "vapt -verify-audit <assessment directory>") {
		t.Error("Appendix C does not say how to verify offline")
	}
	if !strings.Contains(all, "Head hash") {
		t.Error("Appendix C lost the head hash")
	}
}

// The SARIF export carries the same chain head the PDF prints, the raw digests, and the framework mappings.
func TestSARIFIsBoundToTheAuditChain(t *testing.T) {
	a, raws := fixtureAssessment(t)
	b, err := BuildSARIF(a)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string         `json:"id"`
						Properties map[string]any `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Properties map[string]any `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Runs[0].Properties
	entries, _ := a.AuditEntries()
	if p["audit_head_hash"] != entries[len(entries)-1].Hash || int(p["audit_entries"].(float64)) != len(entries) {
		t.Errorf("SARIF head/entries do not match the chain: %v", p)
	}
	if got := len(p["raw_evidence_sha256"].([]any)); got != len(raws) {
		t.Errorf("raw digests in SARIF = %d, want %d", got, len(raws))
	}
	if !strings.Contains(p["verify_with"].(string), "-verify-audit") {
		t.Errorf("verify_with = %v", p["verify_with"])
	}
	seen := map[string]map[string]any{}
	for _, r := range doc.Runs[0].Tool.Driver.Rules {
		seen[r.ID] = r.Properties
	}
	if tac, _ := seen["web:exposed-git"]["mitre_attack_tactics"].([]any); len(tac) != 1 || tac[0] != "TA0043 Reconnaissance" {
		t.Errorf("ATT&CK tactic missing from SARIF rule: %v", seen["web:exposed-git"])
	}
	if csf, _ := seen["web:exposed-git"]["nist_csf_2_0"].([]any); len(csf) != 1 || csf[0] != "PR.PS Platform Security" {
		t.Errorf("NIST CSF category missing from SARIF rule: %v", seen["web:exposed-git"])
	}
}

func TestSARIFWithoutBindingStaysValidAndOmitsAuditFields(t *testing.T) {
	b, err := SARIF("A-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "audit_head_hash") {
		t.Error("an unbound export must not claim an audit head")
	}
	if _, err := CheckSARIF(b, nil, nil); err == nil {
		t.Error("CheckSARIF must refuse an export with no binding")
	}
}

func TestCheckSARIFAcceptsMatchingChainAndRejectsOthers(t *testing.T) {
	a, _ := fixtureAssessment(t)
	b, err := BuildSARIF(a)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := a.AuditEntries()
	sealed := map[string]audit.Sealed{}
	a.Lock()
	for i, st := range a.Steps {
		sealed[st.ID] = audit.Sealed{Step: st.ID, SHA256: st.RawSHA256, Seq: i + 2}
	}
	a.Unlock()
	if msg, err := CheckSARIF(b, entries, sealed); err != nil || !strings.Contains(msg, "chain entry #") {
		t.Fatalf("matching export rejected: %v %s", err, msg)
	}
	// a chain that grew after the export (a retest appends entries) still verifies
	grown := append(append([]audit.Entry(nil), entries...), audit.Entry{Seq: len(entries) + 1, Hash: "later"})
	if _, err := CheckSARIF(b, grown, sealed); err != nil {
		t.Errorf("a chain that grew since the export must still accept it: %v", err)
	}
	// a different chain must be rejected
	other := append([]audit.Entry(nil), entries...)
	other[len(other)-1].Hash = strings.Repeat("0", 64)
	if _, err := CheckSARIF(b, other, sealed); err == nil {
		t.Error("export from a different chain was accepted")
	}
	// a swapped raw digest must be rejected
	s2 := map[string]audit.Sealed{}
	for k, v := range sealed {
		s2[k] = v
	}
	v := s2["S-02"]
	v.SHA256 = strings.Repeat("f", 64)
	s2["S-02"] = v
	if _, err := CheckSARIF(b, entries, s2); err == nil {
		t.Error("a SARIF whose raw digest disagrees with the sealed one was accepted")
	}
}
