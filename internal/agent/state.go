// Package agent holds the assessment state machine: plan -> guard -> approve ->
// execute -> ingest -> correlate -> replan -> analyse -> review -> report.
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/adapters"
	"github.com/ayanasarkar/vapt-agent/internal/audit"
	"github.com/ayanasarkar/vapt-agent/internal/llm"
	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// Step is one planned tool run, with the reasoning behind it.
type Step struct {
	ID         string            `json:"id"` // S-01
	Round      int               `json:"round"`
	Tool       string            `json:"tool"`
	Target     string            `json:"target"`
	Options    map[string]string `json:"options,omitempty"`
	Import     string            `json:"import_file,omitempty"`
	Rationale  string            `json:"rationale"`
	Trigger    []string          `json:"trigger_evidence,omitempty"` // evidence/service ids that caused this step
	ProposedBy string            `json:"proposed_by"`                // llm:<name> | rules | analyst
	Kind       scope.Kind        `json:"kind"`
	Mode       string            `json:"mode"`
	Status     string            `json:"status"` // proposed | blocked | pending_approval | approved | running | done | failed | skipped | declined
	Guard      scope.Decision    `json:"guard"`
	Summary    string            `json:"summary,omitempty"`
	Error      string            `json:"error,omitempty"`
	RawFile    string            `json:"raw_file,omitempty"`
	RawSHA256  string            `json:"raw_sha256,omitempty"`
	Started    time.Time         `json:"started,omitempty"`
	Ended      time.Time         `json:"ended,omitempty"`
	Attempts   int               `json:"attempts,omitempty"`
	FindingID  string            `json:"finding_id,omitempty"` // for validation steps
}

// Approval records a human decision on an active validation.
type Approval struct {
	ID        string    `json:"id"`
	StepID    string    `json:"step_id"`
	FindingID string    `json:"finding_id"`
	Module    string    `json:"module"`
	Target    string    `json:"target"`
	Status    string    `json:"status"` // pending | approved | declined
	Analyst   string    `json:"analyst,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Requested time.Time `json:"requested"`
	Decided   time.Time `json:"decided,omitempty"`
	Outcome   string    `json:"outcome,omitempty"`
}

// Message is a chat turn.
type Message struct {
	Time   time.Time `json:"time"`
	Role   string    `json:"role"` // analyst | agent
	Text   string    `json:"text"`
	Source string    `json:"source,omitempty"` // for agent turns: "rules" or "model:<name>" (verified)
}

// Event is a progress/decision line for the live feed.
type Event struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"` // info | decision | warn | error
	Text  string    `json:"text"`
}

// Assessment is the whole state (also written to disk as state.json).
type Assessment struct {
	ID          string                       `json:"id"`
	Created     time.Time                    `json:"created"`
	Request     string                       `json:"request"`
	Hosts       []string                     `json:"hosts"`
	Scope       scope.Scope                  `json:"scope"`
	Criticality map[string]string            `json:"criticality,omitempty"`
	AutoApprove bool                         `json:"auto_approve"`
	Phase       string                       `json:"phase"` // planning | awaiting_approval | running | analysing | review | done
	Model       string                       `json:"model"`
	Messages    []Message                    `json:"messages"`
	Events      []Event                      `json:"events"`
	Steps       []Step                       `json:"steps"`
	Round       int                          `json:"round"`
	Services    []model.Service              `json:"services"`
	Evidence    []model.Evidence             `json:"evidence"`
	Raw         []model.RawFinding           `json:"raw_findings"`
	Findings    []model.Finding              `json:"findings"`
	Approvals   []Approval                   `json:"approvals"`
	Validations map[string]Validated         `json:"validations,omitempty"` // finding key -> outcome
	Limitations []string                     `json:"limitations"`
	Summary     string                       `json:"summary,omitempty"` // AI or rules executive narrative
	SummaryBy   string                       `json:"summary_by,omitempty"`
	Imports     map[string]string            `json:"imports,omitempty"`     // tool -> stored path
	Inferences  map[string][]model.Inference `json:"inferences,omitempty"`  // finding key -> AI/rules inferences
	FindingIDs  map[string]string            `json:"finding_ids,omitempty"` // finding key -> stable ID
	Completed   time.Time                    `json:"completed,omitempty"`

	mu     sync.Mutex
	dir    string
	log    *audit.Log
	reg    *adapters.Registry
	guard  *scope.Guard
	llm    llm.Client
	lim    *scope.Limiter
	cancel func()

	started bool     // Start is idempotent: a double-click must not launch a second planning loop
	cancels []func() // cancel funcs of approved-validation runs, so Stop reaches them too
}

// Validated is a stored approved-validation outcome.
type Validated struct {
	Verdict  string    `json:"verdict"`
	Module   string    `json:"module"`
	Line     string    `json:"line"`
	Evidence string    `json:"evidence_id"`
	Analyst  string    `json:"analyst"`
	Time     time.Time `json:"time"`
}

// Env bundles shared dependencies.
type Env struct {
	DataDir string
	Reg     *adapters.Registry
	LLM     llm.Client
}

// New creates an assessment after validating the scope and target hosts.
func New(env Env, id, request string, sc scope.Scope, hosts []string, crit map[string]string, auto bool) (*Assessment, error) {
	g, err := scope.New(sc)
	if err != nil {
		return nil, fmt.Errorf("scope rejected: %w", err)
	}
	dir := filepath.Join(env.DataDir, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lg, err := audit.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		return nil, err
	}
	a := &Assessment{ID: id, Created: time.Now().UTC(), Request: request, Scope: sc, Criticality: crit, AutoApprove: auto,
		Phase: "planning", Model: env.LLM.Name(), Hosts: hosts, Validations: map[string]Validated{}, Imports: map[string]string{}, Inferences: map[string][]model.Inference{}, FindingIDs: map[string]string{},
		dir: dir, log: lg, reg: env.Reg, guard: g, llm: env.LLM, lim: scope.NewLimiter(sc.MaxReqPerSec)}
	a.audit("analyst", "scope_registered", fmt.Sprintf("scope %q registered (authorization %s)", sc.Name, sc.Authorization), map[string]string{
		"targets": fmt.Sprint(sc.Targets), "exclusions": fmt.Sprint(sc.Exclusions), "allow_active": fmt.Sprint(sc.AllowActive),
		"allow_exploit": fmt.Sprint(sc.AllowExploit), "allow_non_lab": fmt.Sprint(sc.AllowNonLab), "ports": fmt.Sprint(sc.Ports), "tools": fmt.Sprint(sc.AllowedTools)})
	return a, nil
}

// Attribute records which signed-in account opened this assessment, so the trail names a person and not just "analyst".
func (a *Assessment) Attribute(user, role string) {
	a.audit(user, "analyst_session", fmt.Sprintf("assessment opened by account %q (role %s), authenticated by KAVACH sign-in", user, role), map[string]string{"account": user, "role": role})
}

// Dir returns the data directory of this assessment.
func (a *Assessment) Dir() string { return a.dir }

// Lock/Unlock guard the state for readers (the HTTP layer).
func (a *Assessment) Lock()   { a.mu.Lock() }
func (a *Assessment) Unlock() { a.mu.Unlock() }

// AuditEntries returns the chained audit trail and its integrity status.
func (a *Assessment) AuditEntries() ([]audit.Entry, string) {
	es := a.log.Entries()
	if err := audit.VerifyEntries(es); err != nil {
		return es, "BROKEN: " + err.Error()
	}
	if err := a.log.Err(); err != nil {
		return es, "DEGRADED: an entry could not be written to disk (" + err.Error() + ")"
	}
	return es, "verified"
}

func (a *Assessment) audit(actor, typ, summary string, d map[string]string) {
	a.log.Append(actor, typ, summary, d)
}

func (a *Assessment) event(level, text string) {
	a.Events = append(a.Events, Event{Time: time.Now().UTC(), Level: level, Text: text})
	a.save()
}

func (a *Assessment) save() {
	b, err := json.MarshalIndent(a, "", " ")
	if err != nil {
		return
	}
	tmp := filepath.Join(a.dir, "state.json.tmp")
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, filepath.Join(a.dir, "state.json"))
	}
}

// Save persists state (locked by the caller or not shared).
func (a *Assessment) Save() { a.save() }

// Guard exposes the scope guard for read-only checks.
func (a *Assessment) Guard() *scope.Guard { return a.guard }

// Registry exposes the adapter registry.
func (a *Assessment) Registry() *adapters.Registry { return a.reg }

// Cancel stops a running execution.
func (a *Assessment) Cancel() {
	a.mu.Lock()
	c := a.cancel
	extra := append([]func(){}, a.cancels...)
	a.mu.Unlock()
	if c != nil {
		c()
	}
	for _, f := range extra {
		f()
	}
}

// Close releases the audit log file handle (needed on Windows before the data
// directory can be removed).
func (a *Assessment) Close() {
	a.Cancel()
	if a.log != nil {
		a.log.Close()
	}
}
