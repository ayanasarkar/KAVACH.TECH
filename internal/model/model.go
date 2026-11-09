// Package model defines the common data model shared by all adapters, the
// correlation engine, the agent and the report generator.
package model

import "time"

// Service is an observed network service (from a scan or an import).
type Service struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	State   string `json:"state"` // open | closed | filtered
	Name    string `json:"name"`  // http, ssh, ...
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Tool    string `json:"tool"`
	EvID    string `json:"evidence_id,omitempty"`
}

// Basis says how a tool arrived at a finding. It drives calibrated confidence.
type Basis string

const (
	BasisDirect   Basis = "direct"           // the vulnerable condition itself was observed
	BasisVersion  Basis = "version-inferred" // inferred from a product/version string
	BasisReported Basis = "tool-reported"    // imported verdict without our own observation
)

// Evidence is one immutable observation with a pointer to its raw source.
type Evidence struct {
	ID      string    `json:"id"` // E-0001
	Tool    string    `json:"tool"`
	Asset   string    `json:"asset"` // host:port or host
	Time    time.Time `json:"time"`
	RawRef  string    `json:"raw_ref"` // e.g. run-2/webcheck.txt#L14 or file name + plugin id
	Excerpt string    `json:"excerpt"` // verbatim text from the tool output
	RunID   string    `json:"run_id"`
}

// RawFinding is what an adapter emits before correlation.
type RawFinding struct {
	Tool         string   `json:"tool"`
	Key          string   `json:"key"` // normalised vulnerability identity, e.g. cve:CVE-2020-1234
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Proto        string   `json:"proto,omitempty"`
	Severity     string   `json:"severity"` // info|low|medium|high|critical (tool-reported)
	CVSS         *float64 `json:"cvss,omitempty"`
	CVSSVector   string   `json:"cvss_vector,omitempty"`
	CVEs         []string `json:"cves,omitempty"`
	CWEs         []string `json:"cwes,omitempty"`
	OWASP        string   `json:"owasp,omitempty"`
	Basis        Basis    `json:"basis"`
	ToolConf     *float64 `json:"tool_confidence,omitempty"`   // 0..1 only if the tool reports one
	ExploitAvail *bool    `json:"exploit_available,omitempty"` // only if the tool reports it
	Remediation  string   `json:"remediation,omitempty"`
	References   []string `json:"references,omitempty"`
	Excerpt      string   `json:"excerpt"` // verbatim supporting output
	RawRef       string   `json:"raw_ref"`
	Evidence     string   `json:"evidence_id,omitempty"` // assigned by the store
}

// Affected is one asset a finding applies to.
type Affected struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Service  string   `json:"service,omitempty"`
	Evidence []string `json:"evidence"`
	Tools    []string `json:"tools"`
}

// Factor is one transparent term in the risk calculation.
type Factor struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Source string  `json:"source"` // why this value
}

// Risk is computed only by code in internal/risk.
type Risk struct {
	Score    float64  `json:"score"` // 0..100
	Priority string   `json:"priority"`
	Factors  []Factor `json:"factors"`
}

// Inference is AI-generated reasoning. It is stored apart from observations and
// must cite evidence IDs that exist.
type Inference struct {
	Text  string   `json:"text"`
	Cites []string `json:"cites"`
	By    string   `json:"by"` // model name or "rules"
}

// Finding is a correlated, deduplicated result.
type Finding struct {
	ID           string      `json:"id"` // F-001
	Title        string      `json:"title"`
	Description  string      `json:"description"`
	Key          string      `json:"key"`
	Severity     string      `json:"severity"`
	CVSS         *float64    `json:"cvss,omitempty"`
	CVSSVector   string      `json:"cvss_vector,omitempty"`
	CVSSSource   string      `json:"cvss_source,omitempty"` // which tool reported the score
	CVEs         []string    `json:"cves,omitempty"`
	CWEs         []string    `json:"cwes,omitempty"`
	OWASP        string      `json:"owasp,omitempty"`
	Assets       []Affected  `json:"assets"`
	Tools        []string    `json:"tools"`
	Evidence     []string    `json:"evidence"`
	Confidence   float64     `json:"confidence"`
	ConfLabel    string      `json:"confidence_label"`
	Status       string      `json:"status"`     // confirmed | suspected | likely_false_positive
	Validation   string      `json:"validation"` // not_validated | pending_approval | validated | validation_failed | declined
	Basis        Basis       `json:"basis"`
	ExploitAvail string      `json:"exploit_available"` // yes | no | unknown (as reported by tools)
	Risk         Risk        `json:"risk"`
	Remediation  string      `json:"remediation"`
	References   []string    `json:"references,omitempty"`
	Notes        []string    `json:"notes,omitempty"` // correlation / triage notes (observed by code)
	Inferences   []Inference `json:"inferences,omitempty"`
	FirstSeen    time.Time   `json:"first_seen"`
	LastSeen     time.Time   `json:"last_seen"`
}

// SevRank orders severities.
func SevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
