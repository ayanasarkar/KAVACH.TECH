package report

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ayanasarkar/vapt-agent/internal/agent"
	"github.com/ayanasarkar/vapt-agent/internal/audit"
	"github.com/ayanasarkar/vapt-agent/internal/model"
)

// SARIF 2.1.0 export. Only what the tools and the code produced goes in: findings, severities, evidence IDs and
// code-computed scores. AI-generated inferences are deliberately left out, so the file holds observations only.

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      *sarifText     `json:"fullDescription,omitempty"`
	Help                 *sarifText     `json:"help,omitempty"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type sarifLogical struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level"`
	Message             sarifText          `json:"message"`
	Locations           []sarifLocation    `json:"locations,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRun struct {
	Tool struct {
		Driver sarifDriver `json:"driver"`
	} `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func sarifAssetURI(a model.Affected) string {
	if a.Port > 0 {
		return "tcp://" + net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
	}
	if strings.Contains(a.Host, ":") {
		return "tcp://[" + a.Host + "]"
	}
	return "tcp://" + a.Host
}

func sarifList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// SARIF renders findings as a SARIF 2.1.0 log: one rule per finding key, one result per finding, one location per
// affected host:port. Findings keep the order they were given (already ordered by risk).
func SARIF(assessmentID string, findings []model.Finding) ([]byte, error) {
	return SARIFWithAudit(assessmentID, findings, AuditBinding{})
}

// Property names under runs[0].properties that bind the export to the audit chain. CheckSARIF reads the same
// constants, so writer and verifier cannot drift apart.
const (
	sarifKeyHead    = "audit_head_hash"
	sarifKeyEntries = "audit_entries"
	sarifKeyStatus  = "audit_chain_status"
	sarifKeyRaw     = "raw_evidence_sha256"
	sarifKeyVerify  = "verify_with"
)

// RawDigest is the SHA-256 of one raw tool output, as sealed in that step's run_end audit entry.
type RawDigest struct {
	Step   string `json:"step"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// AuditBinding ties an export to the hash-chained audit log: the chain head at export time, how many entries
// the chain had, and the digest of every raw tool output. A zero binding (no head hash) leaves it out.
type AuditBinding struct {
	HeadHash string
	Entries  int
	Status   string
	Raw      []RawDigest
}

// bindingOf reads the binding from live state. The caller must hold the assessment lock.
func bindingOf(a *agent.Assessment) AuditBinding {
	entries, status := a.AuditEntries()
	b := AuditBinding{Entries: len(entries), Status: status}
	if len(entries) > 0 {
		b.HeadHash = entries[len(entries)-1].Hash
	}
	for _, st := range a.Steps {
		if st.RawSHA256 != "" && st.RawFile != "" {
			b.Raw = append(b.Raw, RawDigest{Step: st.ID, File: filepath.ToSlash(st.RawFile), SHA256: st.RawSHA256})
		}
	}
	return b
}

// BuildSARIF renders the SARIF export for an assessment with the audit binding included. It reads the state
// under its lock, like Build.
func BuildSARIF(a *agent.Assessment) ([]byte, error) {
	a.Lock()
	defer a.Unlock()
	return SARIFWithAudit(a.ID, a.Findings, bindingOf(a))
}

// SARIFWithAudit is SARIF plus the audit binding (see AuditBinding).
func SARIFWithAudit(assessmentID string, findings []model.Finding, ab AuditBinding) ([]byte, error) {
	rules := []sarifRule{}
	idx := map[string]int{}
	results := []sarifResult{}
	for _, f := range findings {
		rid := f.Key
		if rid == "" {
			rid = f.ID
		}
		i, seen := idx[rid]
		if !seen {
			r := sarifRule{ID: rid, ShortDescription: sarifText{Text: f.Title}, DefaultConfiguration: sarifConfig{Level: sarifLevel(f.Severity)}}
			if f.Description != "" {
				r.FullDescription = &sarifText{Text: f.Description}
			}
			if f.Remediation != "" {
				r.Help = &sarifText{Text: f.Remediation}
			}
			tags := []string{"security", "kavach"}
			for _, c := range f.CWEs {
				tags = append(tags, "external/cwe/"+strings.ToLower(c))
			}
			r.Properties = map[string]any{"tags": tags}
			if tac, csf := frameworkLists(f.CWEs); len(tac) > 0 {
				r.Properties["mitre_attack_tactics"] = tac
				r.Properties["nist_csf_2_0"] = csf
			}
			if f.CVSS != nil {
				r.Properties["security-severity"] = fmt.Sprintf("%.1f", *f.CVSS)
			}
			i = len(rules)
			idx[rid] = i
			rules = append(rules, r)
		}
		msg := strings.TrimSpace(f.ID + ": " + f.Title)
		if f.Description != "" {
			msg += ". " + strings.TrimSpace(f.Description)
		}
		res := sarifResult{RuleID: rid, RuleIndex: i, Level: sarifLevel(f.Severity), Message: sarifText{Text: msg},
			PartialFingerprints: map[string]string{"kavachFinding/v1": rid}}
		for _, a := range f.Assets {
			uri := sarifAssetURI(a)
			res.Locations = append(res.Locations, sarifLocation{
				PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}},
				LogicalLocations: []sarifLogical{{Name: strings.TrimPrefix(uri, "tcp://"), Kind: "resource"}}})
		}
		if f.Status == "likely_false_positive" {
			res.Suppressions = []sarifSuppression{{Kind: "external", Status: "underReview",
				Justification: "KAVACH triaged this as a likely false positive. It is a triage suggestion, not a confirmed dismissal."}}
		}
		props := map[string]any{
			"finding_id": f.ID, "status": f.Status, "confidence": f.Confidence, "confidence_label": f.ConfLabel,
			"validation": f.Validation, "basis": fmt.Sprint(f.Basis), "risk_score": f.Risk.Score, "priority": f.Risk.Priority,
			"tools": sarifList(f.Tools), "evidence": sarifList(f.Evidence),
		}
		if len(f.CVEs) > 0 {
			props["cves"] = f.CVEs
		}
		if len(f.CWEs) > 0 {
			props["cwes"] = f.CWEs
		}
		if f.OWASP != "" {
			props["owasp"] = f.OWASP
		}
		res.Properties = props
		results = append(results, res)
	}
	var run sarifRun
	run.Tool.Driver = sarifDriver{Name: "KAVACH", Rules: rules}
	run.Results = results
	run.Properties = map[string]any{"assessment_id": assessmentID,
		"note": "Findings are correlated by KAVACH. Evidence IDs trace each result to raw tool output. AI-generated inferences are not included."}
	if ab.HeadHash != "" {
		run.Properties[sarifKeyHead] = ab.HeadHash
		run.Properties[sarifKeyEntries] = ab.Entries
		run.Properties[sarifKeyStatus] = ab.Status
		run.Properties[sarifKeyRaw] = ab.Raw
		if ab.Raw == nil {
			run.Properties[sarifKeyRaw] = []RawDigest{}
		}
		run.Properties[sarifKeyVerify] = "vapt -verify-audit <assessment directory> -sarif <this file>"
	}
	return json.MarshalIndent(sarifLog{Schema: sarifSchema, Version: "2.1.0", Runs: []sarifRun{run}}, "", "  ")
}

// CheckSARIF verifies a SARIF export against the chain it was bound to. It confirms that the recorded head hash
// is really entry #N of the log, and that every raw-output digest in the file equals the one sealed in the chain.
// The chain may have grown since the export (a retest appends entries); that is fine, the head just has to sit at
// position N. It returns a one-line description of what agreed, or an error saying what did not.
func CheckSARIF(sarif []byte, entries []audit.Entry, sealed map[string]audit.Sealed) (string, error) {
	var doc struct {
		Runs []struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif, &doc); err != nil || len(doc.Runs) == 0 {
		return "", fmt.Errorf("not a SARIF log")
	}
	p := doc.Runs[0].Properties
	var head string
	var n int
	if json.Unmarshal(p[sarifKeyHead], &head) != nil || head == "" {
		return "", fmt.Errorf("the SARIF carries no %s (exported before the audit binding existed)", sarifKeyHead)
	}
	if json.Unmarshal(p[sarifKeyEntries], &n) != nil || n < 1 || n > len(entries) {
		return "", fmt.Errorf("%s=%d is outside the %d-entry chain", sarifKeyEntries, n, len(entries))
	}
	if entries[n-1].Hash != head {
		return "", fmt.Errorf("%s does not match chain entry #%d (the SARIF was not produced from this audit log)", sarifKeyHead, n)
	}
	var raws []RawDigest
	_ = json.Unmarshal(p[sarifKeyRaw], &raws)
	for _, r := range raws {
		s, ok := sealed[r.Step]
		if !ok {
			return "", fmt.Errorf("SARIF lists a digest for %s, but no run_end entry sealed one", r.Step)
		}
		if !strings.EqualFold(s.SHA256, r.SHA256) {
			return "", fmt.Errorf("raw digest for %s (%s) disagrees with the one sealed in chain entry #%d", r.Step, r.File, s.Seq)
		}
	}
	return fmt.Sprintf("audit_head_hash is chain entry #%d of %d; %d raw digests agree with the sealed ones", n, len(entries), len(raws)), nil
}
