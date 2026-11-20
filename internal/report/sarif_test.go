package report

import (
	"encoding/json"
	"testing"

	"github.com/ayanasarkar/vapt-agent/internal/model"
)

func sarifFixture() []model.Finding {
	cvss := 9.8
	return []model.Finding{
		{ID: "F-001", Key: "web:exposed-env", Title: "Exposed .env file", Description: "The file is readable.", Severity: "high", CVSS: &cvss,
			CWEs: []string{"CWE-538"}, Status: "confirmed", Tools: []string{"webcheck"}, Evidence: []string{"E-0002"},
			Remediation: "Remove the file.", Assets: []model.Affected{{Host: "127.0.0.1", Port: 8081}}},
		{ID: "F-002", Key: "svc:telnet", Title: "Cleartext Telnet", Severity: "medium", Status: "suspected", Tools: []string{"nmap"}, Evidence: []string{"E-0001"},
			Assets: []model.Affected{{Host: "127.0.0.1", Port: 23}, {Host: "::1", Port: 23}}},
		{ID: "F-003", Key: "web:exposed-env", Title: "Exposed .env file", Severity: "high", Status: "likely_false_positive",
			Assets: []model.Affected{{Host: "127.0.0.1", Port: 9000}}},
		{ID: "F-004", Key: "web:version-disclosure:server", Title: "Server header", Severity: "info", Assets: []model.Affected{{Host: "10.0.0.5"}}},
	}
}

func sarifDecode(t *testing.T, findings []model.Finding) map[string]any {
	t.Helper()
	b, err := SARIF("A-1", findings)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	return m
}

func sarifRun0(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	runs, ok := m["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("want exactly one run, got %v", m["runs"])
	}
	return runs[0].(map[string]any)
}

func sarifLists(t *testing.T, run map[string]any) (rules, results []any) {
	t.Helper()
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules, ok1 := driver["rules"].([]any)
	results, ok2 := run["results"].([]any)
	if !ok1 || !ok2 {
		t.Fatalf("rules and results must be arrays, not null: %v / %v", driver["rules"], run["results"])
	}
	return rules, results
}

func TestSarifStructure(t *testing.T) {
	m := sarifDecode(t, sarifFixture())
	if m["version"] != "2.1.0" || m["$schema"] == "" {
		t.Errorf("version %v, schema %v", m["version"], m["$schema"])
	}
	driver := sarifRun0(t, m)["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "KAVACH" {
		t.Errorf("driver name %v", driver["name"])
	}
}

func TestSarifRulesAreSharedByKey(t *testing.T) {
	rules, results := sarifLists(t, sarifRun0(t, sarifDecode(t, sarifFixture())))
	if len(rules) != 3 || len(results) != 4 {
		t.Fatalf("want 3 rules and 4 results, got %d and %d", len(rules), len(results))
	}
	for i, r := range results {
		res := r.(map[string]any)
		ix := int(res["ruleIndex"].(float64))
		if rules[ix].(map[string]any)["id"] != res["ruleId"] {
			t.Errorf("result %d: ruleIndex %d does not point at rule %v", i, ix, res["ruleId"])
		}
	}
	if results[0].(map[string]any)["ruleIndex"] != results[2].(map[string]any)["ruleIndex"] {
		t.Error("two findings with the same key must share one rule")
	}
}

func TestSarifLevels(t *testing.T) {
	cases := map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note", "": "note"}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", sev, got, want)
		}
	}
	_, results := sarifLists(t, sarifRun0(t, sarifDecode(t, sarifFixture())))
	if results[0].(map[string]any)["level"] != "error" || results[1].(map[string]any)["level"] != "warning" || results[3].(map[string]any)["level"] != "note" {
		t.Errorf("unexpected levels in %v", results)
	}
}

func TestSarifLocations(t *testing.T) {
	_, results := sarifLists(t, sarifRun0(t, sarifDecode(t, sarifFixture())))
	uris := func(i int) []string {
		var out []string
		for _, l := range results[i].(map[string]any)["locations"].([]any) {
			out = append(out, l.(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string))
		}
		return out
	}
	if got := uris(1); len(got) != 2 || got[0] != "tcp://127.0.0.1:23" || got[1] != "tcp://[::1]:23" {
		t.Errorf("got %v", got)
	}
	if got := uris(3); len(got) != 1 || got[0] != "tcp://10.0.0.5" {
		t.Errorf("a finding with no port should give a host-only URI, got %v", got)
	}
}

func TestSarifSuppressesOnlyLikelyFalsePositives(t *testing.T) {
	_, results := sarifLists(t, sarifRun0(t, sarifDecode(t, sarifFixture())))
	if _, has := results[0].(map[string]any)["suppressions"]; has {
		t.Error("a confirmed finding must not carry a suppression")
	}
	sup, ok := results[2].(map[string]any)["suppressions"].([]any)
	if !ok || len(sup) != 1 || sup[0].(map[string]any)["kind"] != "external" || sup[0].(map[string]any)["status"] != "underReview" {
		t.Errorf("a likely false positive should be suppressed as under review, got %v", results[2])
	}
}

func TestSarifRuleMetadata(t *testing.T) {
	rules, _ := sarifLists(t, sarifRun0(t, sarifDecode(t, sarifFixture())))
	p0 := rules[0].(map[string]any)["properties"].(map[string]any)
	if p0["security-severity"] != "9.8" {
		t.Errorf("security-severity = %v, want 9.8", p0["security-severity"])
	}
	tagged := false
	for _, tg := range p0["tags"].([]any) {
		if tg == "external/cwe/cwe-538" {
			tagged = true
		}
	}
	if !tagged {
		t.Errorf("CWE tag missing: %v", p0["tags"])
	}
	if _, has := rules[1].(map[string]any)["properties"].(map[string]any)["security-severity"]; has {
		t.Error("security-severity must only appear when a tool reported a CVSS score")
	}
}

func TestSarifEmptyIsValid(t *testing.T) {
	rules, results := sarifLists(t, sarifRun0(t, sarifDecode(t, nil)))
	if len(rules) != 0 || len(results) != 0 {
		t.Errorf("want empty arrays, got %d rules and %d results", len(rules), len(results))
	}
}
