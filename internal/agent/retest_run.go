package agent

import (
	"context"
	"fmt"
	"time"
)

// retestCounts summarises a delta, e.g. "1 NEW, 2 PERSISTING, 1 REMEDIATED, 0 UNVERIFIED".
func retestCounts(items []RetestChange) string {
	n := map[string]int{}
	for _, it := range items {
		n[it.Change]++
	}
	return fmt.Sprintf("%d NEW, %d PERSISTING, %d REMEDIATED, %d UNVERIFIED",
		n[ChangeNew], n[ChangePersisting], n[ChangeRemediated], n[ChangeUnverified])
}

func (a *Assessment) retestByID(id string) *Retest {
	for i := range a.Retests {
		if a.Retests[i].ID == id {
			return &a.Retests[i]
		}
	}
	return nil
}

// latestRun is the newest finished step that ran the same tool on the same endpoint with the same options as s,
// so a second retest is compared with the previous run rather than with the very first one. Caller holds a.mu.
func (a *Assessment) latestRun(s Step) Step {
	want := sig(s.Tool, s.Target, s.Options, s.Import)
	best := s
	for _, st := range a.Steps {
		if st.Status == "done" && sig(st.Tool, st.Target, st.Options, st.Import) == want {
			best = st
		}
	}
	return best
}

// RequestRetest re-runs the tool step that produced a finding as a NEW step (new raw file, new hash) and records
// what changed when it finishes. The original run is never overwritten. The signed-in analyst's request is the
// approval for re-running one already-approved step and is audited under their name; the scope guard checks the
// step when it is added and again at execution time.
func (a *Assessment) RequestRetest(findingID, analyst string) (*Retest, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Phase != "review" && a.Phase != "done" {
		return nil, fmt.Errorf("a retest can only be requested once the assessment has finished (current phase: %s)", a.Phase)
	}
	for _, r := range a.Retests {
		if r.Status == "running" {
			return nil, fmt.Errorf("retest %s is still running", r.ID)
		}
	}
	oi, err := a.originStep(findingID)
	if err != nil {
		return nil, err
	}
	origin := a.Steps[oi]
	base := a.latestRun(origin)
	opts := make(map[string]string, len(origin.Options))
	for k, v := range origin.Options {
		opts[k] = v
	}
	p := proposal{Tool: origin.Tool, Target: origin.Target, Options: opts, Trigger: origin.Trigger,
		Rationale: fmt.Sprintf("Analyst %s requested a retest of %s: re-running %s on %s to compare with %s.", analyst, findingID, origin.Tool, origin.Target, base.ID)}
	before := len(a.Steps)
	if !a.addStep(p, "retest") {
		return nil, fmt.Errorf("the retest step could not be added")
	}
	st := &a.Steps[before]
	switch st.Status {
	case "blocked":
		return nil, fmt.Errorf("the scope guard refused the retest: %s", st.Guard.Reason)
	case "skipped":
		return nil, fmt.Errorf("%s is not available, so it cannot be re-run: %s", origin.Tool, st.Error)
	case "pending_approval":
		st.Status = "declined"
		return nil, fmt.Errorf("this step needs explicit human approval and is not offered as a one-click retest")
	}
	st.Status = "approved"
	rt := Retest{ID: fmt.Sprintf("R-%02d", len(a.Retests)+1), FindingID: findingID, OldStep: base.ID, NewStep: st.ID,
		Analyst: analyst, Requested: time.Now().UTC(), Status: "running"}
	a.Retests = append(a.Retests, rt)
	a.audit("analyst:"+analyst, "retest_requested",
		fmt.Sprintf("%s: retest of %s, re-running %s %s as %s; the %s run and its raw file are kept", rt.ID, findingID, st.Tool, st.Target, st.ID, base.ID),
		map[string]string{"retest": rt.ID, "finding": findingID, "old_step": base.ID, "new_step": st.ID})
	a.event("decision", fmt.Sprintf("Retest %s requested for %s by %s. %s on %s will be re-run as %s and compared with %s; the original run stays on record.",
		rt.ID, findingID, analyst, st.Tool, st.Target, st.ID, base.ID))
	ctx, cancel := context.WithCancel(context.Background())
	a.cancels = append(a.cancels, cancel)
	go a.runRetest(ctx, cancel, rt.ID, before, base.ID)
	return &rt, nil
}

func (a *Assessment) runRetest(ctx context.Context, cancel context.CancelFunc, id string, idx int, oldStep string) {
	defer cancel()
	a.runStep(ctx, idx)
	a.mu.Lock()
	defer a.mu.Unlock()
	rt := a.retestByID(id)
	if rt == nil {
		return
	}
	st := a.Steps[idx]
	rt.Completed = time.Now().UTC()
	if st.Status != "done" {
		why := st.Error
		if why == "" {
			why = st.Guard.Reason
		}
		if why == "" {
			why = "status " + st.Status
		}
		rt.Status = "failed"
		a.audit("agent", "retest_end", fmt.Sprintf("%s FAILED: %s did not complete (%s)", rt.ID, st.ID, why),
			map[string]string{"retest": rt.ID, "new_step": st.ID, "status": "failed"})
		a.event("warn", fmt.Sprintf("Retest %s failed: %s did not complete (%s).", rt.ID, st.ID, why))
		return
	}
	rt.Status = "done"
	rt.Delta = a.retestDelta(oldStep, st.ID)
	sum := retestCounts(rt.Delta)
	a.audit("agent", "retest_end", fmt.Sprintf("%s done: %s compared with %s: %s", rt.ID, st.ID, oldStep, sum),
		map[string]string{"retest": rt.ID, "old_step": oldStep, "new_step": st.ID, "sha256": st.RawSHA256, "status": "done"})
	a.event("decision", fmt.Sprintf("Retest %s finished: %s.", rt.ID, sum))
}
