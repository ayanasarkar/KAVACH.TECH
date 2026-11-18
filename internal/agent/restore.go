package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/ayanasarkar/vapt-agent/internal/audit"
	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// maxRestored bounds start-up work and open audit-log handles when data\ holds many old runs.
const maxRestored = 60

// Restore rebuilds one assessment from <dir>\state.json, which save() writes after every change.
// The JSON carries the data; the guard, rate limiter, audit log and shared dependencies are not
// saved, so they are rebuilt here the way New builds them. The audit log is reopened, not
// recreated, so its hash chain continues from the last entry.
func Restore(env Env, dir string) (*Assessment, error) {
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return nil, err
	}
	a := &Assessment{}
	if err := json.Unmarshal(b, a); err != nil {
		return nil, fmt.Errorf("unreadable state.json: %w", err)
	}
	if a.ID == "" || a.ID != filepath.Base(dir) {
		return nil, fmt.Errorf("state.json id %q does not match its folder", a.ID)
	}
	g, err := scope.New(a.Scope)
	if err != nil {
		return nil, fmt.Errorf("scope rejected: %w", err)
	}
	lg, err := audit.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		return nil, err
	}
	a.dir, a.log, a.reg, a.guard, a.llm = dir, lg, env.Reg, g, env.LLM
	a.lim = scope.NewLimiter(a.Scope.MaxReqPerSec)
	a.started = true // never re-plan over restored results
	if a.Validations == nil {
		a.Validations = map[string]Validated{}
	}
	if a.Imports == nil {
		a.Imports = map[string]string{}
	}
	if a.Inferences == nil {
		a.Inferences = map[string][]model.Inference{}
	}
	if a.FindingIDs == nil {
		a.FindingIDs = map[string]string{}
	}
	switch a.Phase {
	case "planning", "running", "analysing":
		was := a.Phase
		for i := range a.Steps {
			if a.Steps[i].Status == "running" {
				a.Steps[i].Status = "failed"
			}
		}
		a.Phase = "review"
		a.Limitations = append(a.Limitations, "This assessment was interrupted by a server restart, so its results may be incomplete.")
		a.audit("system", "run_interrupted", "server restarted while this assessment was "+was+"; marked for review", map[string]string{"phase": was})
		a.event("info", "The server restarted while this assessment was "+was+". Results so far are kept; the run was not resumed.")
	}
	return a, nil
}

// RestoreAll restores the newest saved assessments under env.DataDir. Folders without a
// state.json (such as auth) are ignored; unreadable ones are reported in problems and skipped.
func RestoreAll(env Env) ([]*Assessment, []string) {
	ents, err := os.ReadDir(env.DataDir)
	if err != nil {
		return nil, []string{err.Error()}
	}
	names := []string{}
	for _, e := range ents {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names))) // ids start with a timestamp, so this is newest first
	var out []*Assessment
	var problems []string
	for _, n := range names {
		dir := filepath.Join(env.DataDir, n)
		if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
			continue
		}
		if len(out) >= maxRestored {
			problems = append(problems, fmt.Sprintf("older assessments beyond the newest %d (left on disk)", maxRestored))
			break
		}
		a, err := Restore(env, dir)
		if err != nil {
			problems = append(problems, n+": "+err.Error())
			continue
		}
		out = append(out, a)
	}
	return out, problems
}
