package agent

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ayanasarkar/vapt-agent/internal/model"
)

func svcEv(id, step, asset string, status int) model.Evidence {
	return model.Evidence{ID: id, Tool: "webcheck", Asset: asset, RunID: step,
		Excerpt: fmt.Sprintf("%s/tcp open service=http product=%q banner=%q", asset, "", fmt.Sprintf("HTTP %d title=%q", status, "t"))}
}

func rawF(tool, key, sev, host string, port int, ev string) model.RawFinding {
	return model.RawFinding{Tool: tool, Key: key, Title: key, Severity: sev, Host: host, Port: port, Evidence: ev}
}

func changesByKey(items []RetestChange) map[string]string {
	m := map[string]string{}
	for _, it := range items {
		m[it.Key] = it.Change
	}
	return m
}

// S-01 found .env and a missing header on 127.0.0.1:8081. S-05 is the retest of the same target.
// newStatus 0 means the retest produced no evidence at all; withFindings adds the retest's own results.
func retestFixture(newStatus int, withFindings bool) *Assessment {
	host := "127.0.0.1:8081"
	a := &Assessment{
		Steps: []Step{
			{ID: "S-01", Tool: "webcheck", Target: "http://127.0.0.1:8081", Status: "done"},
			{ID: "S-05", Tool: "webcheck", Target: "http://127.0.0.1:8081", Status: "done"},
		},
		FindingIDs: map[string]string{"web:exposed-env": "F-001", "web:missing-header:hsts": "F-002"},
		Evidence: []model.Evidence{
			svcEv("E-0001", "S-01", host, 200),
			{ID: "E-0002", Tool: "webcheck", Asset: host, RunID: "S-01"},
			{ID: "E-0003", Tool: "webcheck", Asset: host, RunID: "S-01"},
		},
		Raw: []model.RawFinding{
			rawF("webcheck", "web:exposed-env", "high", "127.0.0.1", 8081, "E-0002"),
			rawF("webcheck", "web:missing-header:hsts", "low", "127.0.0.1", 8081, "E-0003"),
		},
	}
	if newStatus != 0 {
		a.Evidence = append(a.Evidence, svcEv("E-0010", "S-05", host, newStatus))
	}
	if withFindings {
		a.Evidence = append(a.Evidence,
			model.Evidence{ID: "E-0011", Tool: "webcheck", Asset: host, RunID: "S-05"},
			model.Evidence{ID: "E-0012", Tool: "webcheck", Asset: host, RunID: "S-05"})
		a.Raw = append(a.Raw,
			rawF("webcheck", "web:missing-header:hsts", "low", "127.0.0.1", 8081, "E-0011"),
			rawF("webcheck", "web:directory-listing", "medium", "127.0.0.1", 8081, "E-0012"))
	}
	return a
}

func TestRetestDeltaNewPersistingRemediated(t *testing.T) {
	a := retestFixture(200, true)
	items := a.retestDelta("S-01", "S-05")
	want := map[string]string{
		"web:exposed-env":         ChangeRemediated,
		"web:missing-header:hsts": ChangePersisting,
		"web:directory-listing":   ChangeNew,
	}
	if got := changesByKey(items); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if items[0].Change != ChangeNew || items[len(items)-1].Change != ChangeRemediated {
		t.Errorf("expected NEW first and REMEDIATED last, got %+v", items)
	}
	for _, it := range items {
		if it.Key == "web:exposed-env" && it.FindingID != "F-001" {
			t.Errorf("finding id not carried over: %+v", it)
		}
	}
}

func TestRetestDeltaDoesNotClaimRemediationFromAnErrorPage(t *testing.T) {
	a := retestFixture(523, false)
	got := changesByKey(a.retestDelta("S-01", "S-05"))
	if len(got) != 2 {
		t.Fatalf("expected 2 items, got %v", got)
	}
	for key, ch := range got {
		if ch != ChangeUnverified {
			t.Errorf("%s: a 523 retest must not claim %s", key, ch)
		}
	}
}

func TestRetestDeltaNothingObservedIsUnverified(t *testing.T) {
	a := retestFixture(0, false)
	for key, ch := range changesByKey(a.retestDelta("S-01", "S-05")) {
		if ch != ChangeUnverified {
			t.Errorf("%s: got %s, want UNVERIFIED when the retest saw nothing from the host", key, ch)
		}
	}
}

func TestRetestDeltaPortScannerAbsenceIsRemediation(t *testing.T) {
	a := &Assessment{
		Steps: []Step{{ID: "S-01", Tool: "nmap", Status: "done"}, {ID: "S-02", Tool: "nmap", Status: "done"}},
		Evidence: []model.Evidence{
			{ID: "E-0001", Tool: "nmap", Asset: "10.0.0.5:21", RunID: "S-01"},
			{ID: "E-0002", Tool: "nmap", Asset: "10.0.0.5:22", RunID: "S-01"},
			{ID: "E-0003", Tool: "nmap", Asset: "10.0.0.5:22", RunID: "S-02"},
		},
		Raw: []model.RawFinding{
			rawF("nmap", "svc:ftp-anon", "high", "10.0.0.5", 21, "E-0001"),
			rawF("nmap", "svc:ssh-old", "low", "10.0.0.5", 22, "E-0002"),
			rawF("nmap", "svc:ssh-old", "low", "10.0.0.5", 22, "E-0003"),
		},
	}
	want := map[string]string{"svc:ftp-anon": ChangeRemediated, "svc:ssh-old": ChangePersisting}
	if got := changesByKey(a.retestDelta("S-01", "S-02")); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOriginStep(t *testing.T) {
	a := &Assessment{
		Steps: []Step{
			{ID: "S-01", Tool: "webcheck", Status: "done"},
			{ID: "S-02", Tool: "nessus", Import: "scan.nessus", Status: "done"},
			{ID: "S-03", Tool: "metasploit", Status: "done"},
			{ID: "S-04", Tool: "nmap", Status: "failed"},
		},
		Evidence: []model.Evidence{
			{ID: "E-0001", RunID: "S-01"}, {ID: "E-0002", RunID: "S-02"}, {ID: "E-0003", RunID: "S-03"}, {ID: "E-0004", RunID: "S-04"},
		},
		Findings: []model.Finding{
			{ID: "F-001", Evidence: []string{"E-0002", "E-0001"}}, // skips the import, finds the live step
			{ID: "F-002", Evidence: []string{"E-0002"}},
			{ID: "F-003", Evidence: []string{"E-0003"}},
			{ID: "F-004", Evidence: []string{"E-0004"}},
		},
	}
	if i, err := a.originStep("F-001"); err != nil || a.Steps[i].ID != "S-01" {
		t.Errorf("F-001: got index %d, err %v; want step S-01", i, err)
	}
	for _, id := range []string{"F-002", "F-003", "F-004", "F-099"} {
		if _, err := a.originStep(id); err == nil {
			t.Errorf("%s must not be retestable", id)
		}
	}
}
