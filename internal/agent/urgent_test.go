package agent

import (
	"strings"
	"testing"

	"github.com/ayanasarkar/vapt-agent/internal/model"
)

func TestUrgentRouting(t *testing.T) {
	for _, q := range []string{
		"summarise what is urgent to fix and why",
		"what should i fix first",
		"ask what to fix first",
		"what are the top priorities",
		"which is the biggest risk",
	} {
		if !urgentRe.MatchString(strings.ToLower(q)) {
			t.Errorf("%q should route to the prioritised list", q)
		}
	}
	for _, q := range []string{"why was nmap chosen", "explain the plan", "which tool ran"} {
		if urgentRe.MatchString(strings.ToLower(q)) {
			t.Errorf("%q should keep the tool-rationale answer", q)
		}
	}
}

func TestUrgentReplyUsesComputedOrder(t *testing.T) {
	var fs []model.Finding
	for i, id := range []string{"F-005", "F-010", "F-013", "F-012", "F-004", "F-006"} {
		f := model.Finding{ID: id, Title: "title " + id, Severity: "high", Status: "confirmed", Tools: []string{"webcheck"}}
		f.Risk.Score = float64(90 - i)
		f.Risk.Priority = "P1"
		fs = append(fs, f)
	}
	got := urgentReply(fs)
	if !strings.Contains(got, "5 of 6") || strings.Contains(got, "F-006") {
		t.Errorf("expected top 5 of 6 without F-006, got:\n%s", got)
	}
	if strings.Index(got, "F-005") > strings.Index(got, "F-010") {
		t.Errorf("findings should stay in risk order:\n%s", got)
	}
	if !strings.Contains(urgentReply(nil), "nothing to prioritise") {
		t.Error("empty findings should say there is nothing to prioritise")
	}
}
