package agent

import (
	"encoding/json"
	"testing"
)

// TestStepOptionsToleratesModelQuirks reproduces the Groq openai/gpt-oss-120b failure
// seen in practice: "json: cannot unmarshal string into Go struct field
// llmPlan.steps.options of type map[string]string", which used to fail the whole
// plan round and silently fall the assessment back to the rules planner.
func TestStepOptionsToleratesModelQuirks(t *testing.T) {
	cases := []struct {
		name string
		js   string
		want stepOptions
	}{
		{"normal object", `{"tool":"nmap","target":"h","options":{"ports":"1-1024"}}`, stepOptions{"ports": "1-1024"}},
		{"null", `{"tool":"nmap","target":"h","options":null}`, stepOptions{}},
		{"omitted", `{"tool":"nmap","target":"h"}`, stepOptions(nil)},
		{"bare string (the observed failure)", `{"tool":"nmap","target":"h","options":"vulners"}`, stepOptions{"raw": "vulners"}},
		{"bare number", `{"tool":"nmap","target":"h","options":0}`, stepOptions{"raw": "0"}},
		{"object with a non-string value", `{"tool":"nmap","target":"h","options":{"ports":1024}}`, stepOptions{"ports": "1024"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var p proposal
			if err := json.Unmarshal([]byte(c.js), &p); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if len(p.Options) != len(c.want) {
				t.Fatalf("got %#v, want %#v", p.Options, c.want)
			}
			for k, v := range c.want {
				if p.Options[k] != v {
					t.Errorf("key %q: got %q, want %q", k, p.Options[k], v)
				}
			}
		})
	}
}

// TestLLMPlanToleratesOneBadStep reproduces the real failure shape: a round with
// several steps where only one has a malformed "options" field. The whole round
// must still decode, not just the one field.
func TestLLMPlanToleratesOneBadStep(t *testing.T) {
	js := `{"reasoning":"r","steps":[
		{"tool":"webcheck","target":"http://h/","options":{},"rationale":"a"},
		{"tool":"nmap","target":"h","options":"vulners","rationale":"b"}
	],"done":false}`
	var p llmPlan
	if err := json.Unmarshal([]byte(js), &p); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(p.Steps) != 2 {
		t.Fatalf("got %d steps, want 2", len(p.Steps))
	}
	if got := p.Steps[1].Options["raw"]; got != "vulners" {
		t.Errorf("second step options[raw] = %q, want %q", got, "vulners")
	}
}

// TestSanitizeOptionsDropsRaw confirms the malformed-value placeholder key can never
// reach an adapter: sanitizeOptions' allow-list does not include "raw" for any tool.
func TestSanitizeOptionsDropsRaw(t *testing.T) {
	out, dropped := sanitizeOptions("nmap", map[string]string{"raw": "vulners"}, intent{})
	if len(out) != 0 {
		t.Errorf("want nothing to pass through, got %#v", out)
	}
	if len(dropped) != 1 {
		t.Errorf("want one dropped entry, got %#v", dropped)
	}
}
