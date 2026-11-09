package risk

import (
	"testing"

	"github.com/ayanasarkar/vapt-agent/internal/model"
)

func TestGap_ScoreSaturates(t *testing.T) {
	mk := func(c float64) *model.Finding {
		return &model.Finding{CVSS: &c, CVSSSource: "t", Severity: "high", Confidence: 0.97, ExploitAvail: "yes", Status: "suspected",
			Assets: []model.Affected{{Host: "h", Port: 80}}}
	}
	ctx := Context{Criticality: map[string]string{"h": "critical"}, Reachable: map[string]bool{"h:80": true}}
	a, b := mk(9.8), mk(8.1)
	Score(a, ctx)
	Score(b, ctx)
	if a.Risk.Score == b.Risk.Score {
		t.Errorf("SATURATION: CVSS 9.8 and CVSS 8.1 both score %.1f, so the ranking cannot tell them apart", a.Risk.Score)
	}
}
