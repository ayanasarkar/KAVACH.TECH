package report

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var literalCWERe = regexp.MustCompile(`CWE-[0-9]+`)

// adapterCWEs scans internal/adapters' non-test source for every "CWE-123" literal the
// adapters actually assign to a finding. It is a static grep, not a Go parser, so it
// also catches a CWE named in a comment; that only makes the check stricter.
func adapterCWEs(t *testing.T) map[string]bool {
	t.Helper()
	dir := filepath.Join("..", "adapters")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	found := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for _, m := range literalCWERe.FindAllString(string(b), -1) {
			found[m] = true
		}
	}
	return found
}

// TestFrameworkCoversEveryAdapterCWE keeps frameworkByCWE honest as the codebase
// changes: if an adapter starts assigning a new CWE, this fails until that CWE gets a
// deliberate tactic/category entry (or an explicit, documented skip) rather than the
// report silently going quiet on it.
func TestFrameworkCoversEveryAdapterCWE(t *testing.T) {
	for cwe := range adapterCWEs(t) {
		if _, ok := frameworkByCWE[cwe]; !ok {
			t.Errorf("adapters assign %s but frameworkByCWE has no entry for it; add one (or document why it's deliberately skipped)", cwe)
		}
	}
}

// TestFrameworkByCWEWellFormed sanity-checks the table's shape: a real ATT&CK Enterprise
// tactic ID (one of the 14 stable TAxxxx ids) and a non-empty CSF category code/name, so
// a typo doesn't silently render as blank or garbled text in the PDF.
func TestFrameworkByCWEWellFormed(t *testing.T) {
	validTactics := map[string]bool{
		"TA0043": true, "TA0042": true, "TA0001": true, "TA0002": true, "TA0003": true,
		"TA0004": true, "TA0005": true, "TA0006": true, "TA0007": true, "TA0008": true,
		"TA0009": true, "TA0011": true, "TA0010": true, "TA0040": true,
	}
	for cwe, fw := range frameworkByCWE {
		if !literalCWERe.MatchString(cwe) {
			t.Errorf("%s is not a well-formed CWE id", cwe)
		}
		if !validTactics[fw.tacticID] {
			t.Errorf("%s: %q is not one of the 14 ATT&CK Enterprise tactic ids", cwe, fw.tacticID)
		}
		if fw.tacticName == "" || fw.csfCat == "" || fw.csfName == "" || fw.why == "" {
			t.Errorf("%s: every field must be filled in", cwe)
		}
	}
}

func TestFrameworkLine(t *testing.T) {
	cases := []struct {
		name string
		cwes []string
		want string
	}{
		{"no cwes", nil, ""},
		{"unmapped cwe", []string{"CWE-9999"}, ""},
		{"single mapped cwe", []string{"CWE-527"},
			"MITRE ATT&CK: Reconnaissance (TA0043)    NIST CSF 2.0: PR.PS Platform Security"},
		{"mix of mapped and unmapped: the mapped one still renders", []string{"CWE-9999", "CWE-538"},
			"MITRE ATT&CK: Credential Access (TA0006)    NIST CSF 2.0: PR.DS Data Security"},
		{"two cwes sharing one tactic and one category de-duplicate", []string{"CWE-1004", "CWE-614"},
			"MITRE ATT&CK: Credential Access (TA0006)    NIST CSF 2.0: PR.DS Data Security"},
		{"lowercase / whitespace input still matches", []string{" cwe-527 "},
			"MITRE ATT&CK: Reconnaissance (TA0043)    NIST CSF 2.0: PR.PS Platform Security"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := frameworkLine(c.cwes); got != c.want {
				t.Errorf("frameworkLine(%v) = %q, want %q", c.cwes, got, c.want)
			}
		})
	}
}
