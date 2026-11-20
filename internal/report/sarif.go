package report

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

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
	return json.MarshalIndent(sarifLog{Schema: sarifSchema, Version: "2.1.0", Runs: []sarifRun{run}}, "", "  ")
}
