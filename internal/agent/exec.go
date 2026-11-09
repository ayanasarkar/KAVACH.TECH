package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/adapters"
	"github.com/ayanasarkar/vapt-agent/internal/correlate"
	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/risk"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// Start validates the request, then plans (and, with auto-approve, executes).
func (a *Assessment) Start() {
	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		return
	}
	a.started = true
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.Messages = append(a.Messages, Message{Time: time.Now().UTC(), Role: "analyst", Text: a.Request})
	a.audit("analyst", "request", a.Request, map[string]string{"hosts": strings.Join(a.Hosts, ",")})
	// Every host the analyst entered is itself checked by the guard.
	var ok []string
	for _, h := range a.Hosts {
		d := a.guard.Check(scope.Action{Tool: "request", Target: h, Kind: scope.KindPassive})
		a.audit("scope-guard", "scope_decision", fmt.Sprintf("target %s: allowed=%v (%s)", h, d.Allowed, d.Reason), map[string]string{"target": h, "allowed": fmt.Sprint(d.Allowed)})
		if d.Allowed {
			ok = append(ok, h)
		} else {
			a.event("warn", fmt.Sprintf("Scope guard REFUSED target %s: %s", h, d.Reason))
		}
	}
	a.Hosts = ok
	a.ingestRequest(a.Request)
	if len(a.Hosts) == 0 {
		a.Phase = "done"
		a.Messages = append(a.Messages, Message{Time: time.Now().UTC(), Role: "agent", Text: "No in-scope target remains, so nothing was planned or run. Check the scope and targets."})
		a.event("error", "No in-scope targets. Assessment stopped without running anything.")
		a.mu.Unlock()
		return
	}
	a.Messages = append(a.Messages, Message{Time: time.Now().UTC(), Role: "agent", Text: fmt.Sprintf("Targets accepted: %s. Building a plan from the request and scope; every step is checked by the scope guard before it can run.", strings.Join(a.Hosts, ", "))})
	a.mu.Unlock()
	go a.loop(ctx, false)
}

func (a *Assessment) loop(ctx context.Context, skipPlan bool) {
	for {
		a.mu.Lock()
		if a.Round >= maxRounds {
			a.mu.Unlock()
			break
		}
		a.Phase = "planning"
		a.mu.Unlock()
		if !skipPlan {
			n := a.planRound(ctx)
			if n == 0 {
				break
			}
			a.mu.Lock()
			if !a.AutoApprove {
				a.Phase = "awaiting_approval"
				a.event("info", fmt.Sprintf("Round %d plan is ready. Waiting for analyst approval before any scan runs.", a.Round))
				a.mu.Unlock()
				return
			}
			a.mu.Unlock()
		}
		skipPlan = false
		a.executeApproved(ctx)
		if ctx.Err() != nil {
			break
		}
		a.mu.Lock()
		a.Round++
		a.mu.Unlock()
	}
	a.finish(ctx)
}

// ApprovePlan approves the listed proposed steps (all if none listed) and resumes.
func (a *Assessment) ApprovePlan(ids []string, analyst string) error {
	a.mu.Lock()
	if a.Phase != "awaiting_approval" {
		a.mu.Unlock()
		return errors.New("no plan is awaiting approval")
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	n := 0
	for i := range a.Steps {
		s := &a.Steps[i]
		if s.Status == "proposed" && (len(want) == 0 || want[s.ID]) {
			s.Status = "approved"
			n++
			a.audit("analyst:"+analyst, "approval", fmt.Sprintf("approved %s (%s on %s)", s.ID, s.Tool, s.Target), map[string]string{"step": s.ID})
		} else if s.Status == "proposed" {
			s.Status = "declined"
			a.audit("analyst:"+analyst, "approval", fmt.Sprintf("declined %s (%s on %s)", s.ID, s.Tool, s.Target), map[string]string{"step": s.ID})
		}
	}
	if n == 0 {
		a.mu.Unlock()
		return errors.New("no steps selected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.Phase = "running"
	a.event("info", fmt.Sprintf("Analyst %s approved %d step(s).", analyst, n))
	a.mu.Unlock()
	go a.loop(ctx, true)
	return nil
}

// DenyPlan declines every proposed step of the waiting plan, records each refusal in the audit chain, and ends the
// assessment with whatever evidence exists so far. Nothing from the denied plan runs and no further round is planned.
func (a *Assessment) DenyPlan(analyst, reason string) error {
	a.mu.Lock()
	if a.Phase != "awaiting_approval" {
		a.mu.Unlock()
		return errors.New("no plan is awaiting approval")
	}
	n := 0
	for i := range a.Steps {
		s := &a.Steps[i]
		if s.Status == "proposed" {
			s.Status = "declined"
			n++
			a.audit("analyst:"+analyst, "approval", fmt.Sprintf("declined %s (%s on %s)", s.ID, s.Tool, s.Target), map[string]string{"step": s.ID, "reason": reason})
		}
	}
	if n == 0 {
		a.mu.Unlock()
		return errors.New("no steps to deny")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.event("warn", fmt.Sprintf("Analyst %s denied the plan (%d step(s)). Nothing from it will run.", analyst, n))
	a.mu.Unlock()
	go a.finish(ctx)
	return nil
}

func (a *Assessment) executeApproved(ctx context.Context) {
	a.mu.Lock()
	a.Phase = "running"
	var idx []int
	for i, s := range a.Steps {
		if s.Status == "approved" && s.Tool != "metasploit" {
			idx = append(idx, i)
		}
	}
	order := map[string]int{"nessus": 0, "openvas": 0, "burp": 0, "nmap": 1, "portscan": 1, "webcheck": 2, "nikto": 3, "zap": 3}
	sort.SliceStable(idx, func(i, j int) bool { return order[a.Steps[idx[i]].Tool] < order[a.Steps[idx[j]].Tool] })
	a.mu.Unlock()
	for _, i := range idx {
		if ctx.Err() != nil {
			return
		}
		a.runStep(ctx, i)
	}
}

func (a *Assessment) runStep(ctx context.Context, i int) {
	a.mu.Lock()
	st := &a.Steps[i]
	ad, _ := a.reg.Get(st.Tool)
	// Defence in depth: re-check scope at the moment of execution.
	if d := a.guard.Check(scope.Action{Tool: st.Tool, Target: st.Target, Kind: ad.Kind()}); !d.Allowed {
		st.Status, st.Guard = "blocked", d
		a.audit("scope-guard", "scope_decision", fmt.Sprintf("%s blocked at execution time: %s", st.ID, d.Reason), map[string]string{"step": st.ID})
		a.event("warn", fmt.Sprintf("%s blocked at execution time: %s", st.ID, d.Reason))
		a.mu.Unlock()
		return
	}
	host, port, _ := scope.SplitTarget(st.Target)
	job := adapters.Job{Target: st.Target, Host: host, Port: port, Options: st.Options, ImportPath: st.Import, Limiter: a.lim,
		AllowedPorts: append([]int(nil), a.Scope.Ports...), MaxReqPerSec: a.Scope.MaxReqPerSec, DialCheck: a.guard.CheckDial,
		AllowPort: func(p int) bool {
			if len(a.Scope.Ports) == 0 {
				return true
			}
			for _, x := range a.Scope.Ports {
				if x == p {
					return true
				}
			}
			return false
		}}
	st.Status, st.Started = "running", time.Now().UTC()
	st.Attempts++
	a.audit("tool:"+st.Tool, "run_start", fmt.Sprintf("%s started: %s %s", st.ID, st.Tool, st.Target), map[string]string{"step": st.ID, "mode": st.Mode})
	a.event("info", fmt.Sprintf("%s running: %s on %s", st.ID, st.Tool, st.Target))
	a.mu.Unlock()

	var res adapters.Result
	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		rctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
		res, err = ad.Run(rctx, job)
		cancel()
		if err == nil || ctx.Err() != nil || !retryable(err) || attempt == 2 {
			break
		}
		a.mu.Lock()
		a.event("warn", fmt.Sprintf("%s attempt %d failed (%v); retrying once.", a.Steps[i].ID, attempt, err))
		a.Steps[i].Attempts++
		a.mu.Unlock()
		time.Sleep(2 * time.Second)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	st = &a.Steps[i]
	st.Ended = time.Now().UTC()
	if res.Raw != "" {
		_ = os.MkdirAll(filepath.Join(a.dir, "raw"), 0o700)
		name := filepath.Join("raw", fmt.Sprintf("%s-%s.txt", st.ID, st.Tool))
		if os.WriteFile(filepath.Join(a.dir, name), []byte(res.Raw), 0o600) == nil {
			st.RawFile = name
			sum := sha256.Sum256([]byte(res.Raw))
			st.RawSHA256 = hex.EncodeToString(sum[:])
		}
	}
	if err != nil {
		st.Status, st.Error = "failed", err.Error()
		a.Limitations = addUniq(a.Limitations, fmt.Sprintf("%s (%s on %s) failed: %s", st.ID, st.Tool, st.Target, err.Error()))
		a.audit("tool:"+st.Tool, "run_end", fmt.Sprintf("%s FAILED: %v", st.ID, err), map[string]string{"step": st.ID, "status": "failed"})
		a.event("error", fmt.Sprintf("%s %s failed: %v — continuing with the remaining steps.", st.ID, st.Tool, err))
		return
	}
	st.Status, st.Summary = "done", res.Summary
	a.audit("tool:"+st.Tool, "run_end", fmt.Sprintf("%s done: %s", st.ID, res.Summary), map[string]string{"step": st.ID, "status": "done", "sha256": st.RawSHA256})
	a.event("info", fmt.Sprintf("%s finished: %s", st.ID, res.Summary))
	a.ingest(st, res)
	if res.Validation != nil {
		a.recordValidation(st, res.Validation)
	}
	a.recompute()
}

func retryable(err error) bool {
	if strings.Contains(err.Error(), "not installed") || strings.Contains(err.Error(), "parse") || strings.Contains(err.Error(), "refusing") {
		return false
	}
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) || strings.Contains(err.Error(), "timed out") || strings.Contains(err.Error(), "refused")
}

func (a *Assessment) newEvidenceID() string { return fmt.Sprintf("E-%04d", len(a.Evidence)+1) }

// ingest stores evidence and raw findings. Results about hosts outside the scope
// (possible in imported files) are discarded and recorded.
func (a *Assessment) ingest(st *Step, res adapters.Result) {
	inScope := func(host string) bool {
		return a.guard.Check(scope.Action{Tool: st.Tool, Target: host, Kind: scope.KindPassive}).Allowed
	}
	dropped := map[string]int{}
	ref := func(r string) string {
		if st.RawFile != "" {
			return st.RawFile + " — " + r
		}
		return r
	}
	for _, s := range res.Services {
		if !inScope(s.Host) {
			dropped[s.Host]++
			continue
		}
		if s.State == "open" {
			e := model.Evidence{ID: a.newEvidenceID(), Tool: s.Tool, Asset: fmt.Sprintf("%s:%d", s.Host, s.Port), Time: time.Now().UTC(),
				RawRef: ref("service record"), Excerpt: fmt.Sprintf("%s:%d/%s open service=%s product=%q banner=%q", s.Host, s.Port, s.Proto, s.Name, s.Product, s.Banner), RunID: st.ID}
			a.Evidence = append(a.Evidence, e)
			s.EvID = e.ID
		}
		replaced := false
		for k := range a.Services {
			if a.Services[k].Host == s.Host && a.Services[k].Port == s.Port && a.Services[k].Tool == s.Tool {
				a.Services[k], replaced = s, true
			}
		}
		if !replaced {
			a.Services = append(a.Services, s)
		}
	}
	for _, f := range res.Findings {
		if !inScope(f.Host) {
			dropped[f.Host]++
			continue
		}
		e := model.Evidence{ID: a.newEvidenceID(), Tool: f.Tool, Asset: fmt.Sprintf("%s:%d", f.Host, f.Port), Time: time.Now().UTC(), RawRef: ref(f.RawRef), Excerpt: f.Excerpt, RunID: st.ID}
		a.Evidence = append(a.Evidence, e)
		f.Evidence = e.ID
		a.Raw = append(a.Raw, f)
	}
	for h, n := range dropped {
		msg := fmt.Sprintf("%d result(s) for %s in the %s output were DISCARDED: host is outside the authorised scope.", n, h, st.Tool)
		a.Limitations = addUniq(a.Limitations, msg)
		a.audit("scope-guard", "scope_decision", msg, map[string]string{"step": st.ID, "host": h})
		a.event("warn", msg)
	}
}

// recompute reruns correlation over everything collected so far (idempotent).
func (a *Assessment) recompute() {
	rc := risk.Context{Criticality: a.Criticality, Reachable: map[string]bool{}}
	for _, s := range a.Services {
		if s.State == "open" && (s.Tool == "portscan" || s.Tool == "nmap" || s.Tool == "webcheck") {
			rc.Reachable[fmt.Sprintf("%s:%d", s.Host, s.Port)] = true
		}
	}
	fs := correlate.Run(correlate.Input{Raw: a.Raw, Services: a.Services, Risk: rc, Now: time.Now().UTC()})
	// Stable IDs: assigned in order of first appearance, never reused.
	next := len(a.FindingIDs) + 1
	byKey := map[string]int{}
	for i := range fs {
		byKey[fs[i].Key] = i
	}
	var keys []string
	for k := range byKey {
		if _, ok := a.FindingIDs[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		a.FindingIDs[k] = fmt.Sprintf("F-%03d", next)
		next++
	}
	for i := range fs {
		fs[i].ID = a.FindingIDs[fs[i].Key]
		fs[i].Inferences = a.Inferences[fs[i].Key]
		if v, ok := a.Validations[fs[i].Key]; ok {
			applyValidation(&fs[i], v)
			risk.Score(&fs[i], rc)
		}
		for _, ap := range a.Approvals {
			if ap.FindingID == fs[i].ID && ap.Status == "pending" {
				fs[i].Validation = "pending_approval"
			} else if ap.FindingID == fs[i].ID && ap.Status == "declined" && fs[i].Validation == "not_validated" {
				fs[i].Validation = "declined"
			}
		}
	}
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Risk.Score > fs[j].Risk.Score })
	a.Findings = fs
}

func applyValidation(f *model.Finding, v Validated) {
	f.Evidence = append(f.Evidence, v.Evidence)
	switch v.Verdict {
	case "vulnerable":
		f.Validation, f.Status = "validated_vulnerable", "confirmed"
		f.Confidence = 0.97
		f.ConfLabel = "high"
		f.Notes = append(f.Notes, fmt.Sprintf("Validated by analyst %s with %s (lab, check-only): %s", v.Analyst, v.Module, v.Line))
	case "not_vulnerable":
		f.Validation = "validation_negative"
		f.Confidence *= 0.6
		f.ConfLabel = "low"
		f.Notes = append(f.Notes, fmt.Sprintf("Validation by %s with %s returned a negative result (%s). A negative check is not proof of absence; confidence reduced.", v.Analyst, v.Module, v.Line))
	default:
		f.Validation = "validation_inconclusive"
		f.Notes = append(f.Notes, fmt.Sprintf("Validation with %s was inconclusive (%s).", v.Module, v.Line))
	}
}

// AddImport registers an analyst-supplied export and re-plans so it is ingested.
func (a *Assessment) AddImport(tool, path string) error {
	if _, ok := a.reg.Get(tool); !ok {
		return fmt.Errorf("unknown tool %q", tool)
	}
	if ad, _ := a.reg.Get(tool); ad.Mode() != adapters.ImportOnl {
		return fmt.Errorf("%s is not an import-only integration", tool)
	}
	a.mu.Lock()
	a.Imports[tool] = path
	a.audit("analyst", "import_registered", fmt.Sprintf("%s export supplied (%s)", tool, filepath.Base(path)), map[string]string{"tool": tool})
	replan := a.Phase == "review" || a.Phase == "done"
	if replan {
		a.Round = 0
		a.Phase = "planning"
	}
	a.save()
	a.mu.Unlock()
	if replan {
		ctx, cancel := context.WithCancel(context.Background())
		a.mu.Lock()
		a.cancel = cancel
		a.mu.Unlock()
		go a.loop(ctx, false)
	}
	return nil
}

// Probe is an audited dry run of the scope guard: it reports whether a target
// would be allowed, and runs nothing.
func (a *Assessment) Probe(target, analyst string) scope.Decision {
	a.mu.Lock()
	defer a.mu.Unlock()
	d := a.guard.Check(scope.Action{Tool: "probe", Target: target, Kind: scope.KindPassive})
	a.audit("analyst:"+analyst, "scope_probe", fmt.Sprintf("dry run: %s allowed=%v (%s); nothing executed", target, d.Allowed, d.Reason),
		map[string]string{"target": target, "allowed": fmt.Sprint(d.Allowed)})
	lv := "info"
	if !d.Allowed {
		lv = "warn"
	}
	a.event(lv, fmt.Sprintf("Scope probe %s: %s (%s). Nothing was executed.", target, map[bool]string{true: "ALLOWED", false: "REFUSED"}[d.Allowed], d.Reason))
	return d
}
