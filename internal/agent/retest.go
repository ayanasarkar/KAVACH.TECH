package agent

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/model"
)

// Labels for one issue when a step is re-run.
const (
	ChangeNew        = "NEW"        // reported by the retest, not by the original step
	ChangePersisting = "PERSISTING" // reported by both runs
	ChangeRemediated = "REMEDIATED" // reported originally, not reproduced, and the retest did reach the asset
	ChangeUnverified = "UNVERIFIED" // reported originally, absent now, but the retest could not judge it
)

// Retest records one re-run of the tool step that produced a finding, and what changed.
// The re-run is a new step with its own raw file and hash; the original is never overwritten.
type Retest struct {
	ID        string         `json:"id"` // R-01
	FindingID string         `json:"finding_id"`
	OldStep   string         `json:"old_step"`
	NewStep   string         `json:"new_step"`
	Analyst   string         `json:"analyst"`
	Requested time.Time      `json:"requested"`
	Completed time.Time      `json:"completed,omitempty"`
	Status    string         `json:"status"` // running | done | failed
	Delta     []RetestChange `json:"delta,omitempty"`
}

// RetestChange is one issue's change between a step and its retest.
type RetestChange struct {
	Key       string `json:"key"`
	FindingID string `json:"finding_id,omitempty"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Asset     string `json:"asset"` // host:port
	Change    string `json:"change"`
}

var retestHTTPStatusRe = regexp.MustCompile(`banner="HTTP (\d{3})`)

func retestAsset(f model.RawFinding) string {
	return strings.ToLower(fmt.Sprintf("%s:%d", f.Host, f.Port))
}

func retestIssueID(f model.RawFinding) string { return f.Key + "|" + retestAsset(f) }

// retestView is what a retest step actually observed.
type retestView struct {
	hosts  map[string]bool // hosts the step produced any evidence for
	status map[string]int  // host:port -> HTTP status the step recorded there
}

// confirmsAbsence says whether the retest could really judge an issue absent. An app-level check (webcheck)
// only counts when the retest saw a 2xx page: a redirect or an error page says nothing about the application.
func (v retestView) confirmsAbsence(f model.RawFinding) bool {
	if !v.hosts[strings.ToLower(f.Host)] {
		return false
	}
	if f.Tool == "webcheck" {
		s := v.status[retestAsset(f)]
		return s >= 200 && s < 300
	}
	return true
}

// issueSet returns the issues one step reported, keyed by finding key + host:port. Caller holds a.mu.
func (a *Assessment) issueSet(stepID string) map[string]model.RawFinding {
	runOf := make(map[string]string, len(a.Evidence))
	for _, e := range a.Evidence {
		runOf[e.ID] = e.RunID
	}
	out := map[string]model.RawFinding{}
	for _, f := range a.Raw {
		if f.Evidence == "" || runOf[f.Evidence] != stepID {
			continue
		}
		if _, dup := out[retestIssueID(f)]; !dup {
			out[retestIssueID(f)] = f
		}
	}
	return out
}

// retestEvidenceView records which hosts and HTTP statuses a step observed. Caller holds a.mu.
func (a *Assessment) retestEvidenceView(stepID string) retestView {
	v := retestView{hosts: map[string]bool{}, status: map[string]int{}}
	for _, e := range a.Evidence {
		if e.RunID != stepID {
			continue
		}
		asset := strings.ToLower(e.Asset)
		if i := strings.LastIndex(asset, ":"); i > 0 {
			v.hosts[asset[:i]] = true
		} else {
			v.hosts[asset] = true
		}
		if m := retestHTTPStatusRe.FindStringSubmatch(e.Excerpt); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				v.status[asset] = n
			}
		}
	}
	return v
}

var retestOrder = map[string]int{ChangeNew: 0, ChangePersisting: 1, ChangeUnverified: 2, ChangeRemediated: 3}

// diffRetest compares what a step reported with what its retest reported.
func diffRetest(oldSet, newSet map[string]model.RawFinding, v retestView, idOf func(key string) string) []RetestChange {
	var out []RetestChange
	add := func(f model.RawFinding, change string) {
		out = append(out, RetestChange{Key: f.Key, FindingID: idOf(f.Key), Title: f.Title, Severity: f.Severity,
			Asset: fmt.Sprintf("%s:%d", f.Host, f.Port), Change: change})
	}
	for id, f := range newSet {
		if _, ok := oldSet[id]; ok {
			add(f, ChangePersisting)
		} else {
			add(f, ChangeNew)
		}
	}
	for id, f := range oldSet {
		if _, ok := newSet[id]; ok {
			continue
		}
		if v.confirmsAbsence(f) {
			add(f, ChangeRemediated)
		} else {
			add(f, ChangeUnverified)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if retestOrder[x.Change] != retestOrder[y.Change] {
			return retestOrder[x.Change] < retestOrder[y.Change]
		}
		if rx, ry := model.SevRank(x.Severity), model.SevRank(y.Severity); rx != ry {
			return rx > ry
		}
		if x.Key != y.Key {
			return x.Key < y.Key
		}
		return x.Asset < y.Asset
	})
	return out
}

// retestDelta compares two finished steps of this assessment. Caller holds a.mu.
func (a *Assessment) retestDelta(oldStep, newStep string) []RetestChange {
	return diffRetest(a.issueSet(oldStep), a.issueSet(newStep), a.retestEvidenceView(newStep),
		func(key string) string { return a.FindingIDs[key] })
}

// originStep finds the finished live step that produced a finding, which is the one a retest re-runs.
// Imported files and approved validation checks cannot be re-run here. Caller holds a.mu.
func (a *Assessment) originStep(findingID string) (int, error) {
	var f *model.Finding
	for i := range a.Findings {
		if a.Findings[i].ID == findingID {
			f = &a.Findings[i]
			break
		}
	}
	if f == nil {
		return -1, fmt.Errorf("unknown finding %q", findingID)
	}
	runOf := make(map[string]string, len(a.Evidence))
	for _, e := range a.Evidence {
		runOf[e.ID] = e.RunID
	}
	for _, eid := range f.Evidence {
		for i := range a.Steps {
			st := a.Steps[i]
			if st.ID == runOf[eid] && st.Status == "done" && st.Import == "" && st.Tool != "metasploit" {
				return i, nil
			}
		}
	}
	return -1, fmt.Errorf("%s came only from an imported file or a validation check, so there is no live tool step to re-run", findingID)
}
