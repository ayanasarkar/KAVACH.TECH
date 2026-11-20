package agent

import (
	"bytes"
	"encoding/json"
	"strings"
)

// evidenceList decodes a model's "trigger_evidence" field. The schema asks for
// an array of evidence/service id strings, but openai/gpt-oss-120b has been
// observed sending objects (e.g. {"id":"E-0003","why":"..."}), a bare string,
// a number or null. Any of those used to fail json.Unmarshal for the whole plan
// response and drop the round back to the rules planner. This type never
// errors: it keeps the id-like strings it can find and discards the rest.
type evidenceList []string

const (
	maxEvidenceRefs   = 16
	maxEvidenceRefLen = 64
)

// keys that may carry the id when the model sends an object instead of a string.
var evidenceKeys = []string{"id", "evidence_id", "evidence", "service_id", "ref"}

func (e *evidenceList) UnmarshalJSON(b []byte) error {
	*e = nil
	var v interface{}
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&v); err != nil {
		return nil // unreadable value: treat as "no evidence cited"
	}
	var out []string
	collectEvidence(v, &out)
	*e = out
	return nil
}

func collectEvidence(v interface{}, out *[]string) {
	if len(*out) >= maxEvidenceRefs {
		return
	}
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		// long strings are prose, not ids; model output is untrusted, so drop them
		if s == "" || len(s) > maxEvidenceRefLen {
			return
		}
		*out = append(*out, s)
	case []interface{}:
		for _, x := range t {
			collectEvidence(x, out)
		}
	case map[string]interface{}:
		for _, k := range evidenceKeys {
			if x, ok := t[k]; ok {
				collectEvidence(x, out)
				return
			}
		}
	}
}
