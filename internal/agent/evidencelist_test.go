package agent

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestProposalTriggerEvidenceShapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"array of strings", `["E-0001","E-0002"]`, []string{"E-0001", "E-0002"}},
		{"null", `null`, nil},
		{"bare string", `"E-0003"`, []string{"E-0003"}},
		{"array of objects", `[{"id":"E-0003","why":"open 80"},{"evidence_id":"E-0004"}]`, []string{"E-0003", "E-0004"}},
		{"single object", `{"id":"E-0005"}`, []string{"E-0005"}},
		{"object with no id", `{"note":"nothing useful"}`, nil},
		{"number", `7`, nil},
		{"prose is dropped", `["` + strings.Repeat("x", 200) + `"]`, nil},
	}
	for _, c := range cases {
		doc := `{"tool":"webcheck","target":"127.0.0.1","options":{},"rationale":"r","trigger_evidence":` + c.in + `}`
		var p proposal
		if err := json.Unmarshal([]byte(doc), &p); err != nil {
			t.Fatalf("%s: unmarshal failed: %v", c.name, err)
		}
		if !reflect.DeepEqual([]string(p.Trigger), c.want) {
			t.Errorf("%s: got %#v, want %#v", c.name, []string(p.Trigger), c.want)
		}
	}
}
