package agent

import "testing"

func TestLatestRunPrefersNewestMatchingDoneStep(t *testing.T) {
	a := &Assessment{Steps: []Step{
		{ID: "S-01", Tool: "webcheck", Target: "http://h:80", Status: "done"},
		{ID: "S-02", Tool: "nmap", Target: "h", Status: "done"},
		{ID: "S-03", Tool: "webcheck", Target: "http://h", Status: "done"},
		{ID: "S-04", Tool: "webcheck", Target: "http://h", Status: "failed"},
		{ID: "S-05", Tool: "webcheck", Target: "http://h:8080", Status: "done"},
	}}
	cases := []struct{ from, want string }{
		{"S-01", "S-03"}, // :80 is the default port, and the failed S-04 does not count
		{"S-02", "S-02"},
		{"S-05", "S-05"},
	}
	for _, c := range cases {
		var s Step
		for _, st := range a.Steps {
			if st.ID == c.from {
				s = st
			}
		}
		if got := a.latestRun(s); got.ID != c.want {
			t.Errorf("latestRun(%s) = %s, want %s", c.from, got.ID, c.want)
		}
	}
}

func TestRequestRetestOnlyAfterFinish(t *testing.T) {
	for _, ph := range []string{"planning", "awaiting_approval", "running", "analysing"} {
		a := &Assessment{Phase: ph}
		if _, err := a.RequestRetest("F-001", "ana"); err == nil {
			t.Errorf("phase %q: a retest must be refused until the assessment has finished", ph)
		}
	}
}

func TestRequestRetestRefusesWhileAnotherIsRunning(t *testing.T) {
	a := &Assessment{Phase: "review", Retests: []Retest{{ID: "R-01", Status: "running"}}}
	if _, err := a.RequestRetest("F-001", "ana"); err == nil {
		t.Error("a second retest must be refused while one is running")
	}
}

func TestRequestRetestRejectsUnknownFinding(t *testing.T) {
	a := &Assessment{Phase: "review"}
	if _, err := a.RequestRetest("F-099", "ana"); err == nil {
		t.Error("an unknown finding must be refused")
	}
	if len(a.Retests) != 0 || len(a.Steps) != 0 {
		t.Error("a refused retest must not create a record or a step")
	}
}

func TestRetestCounts(t *testing.T) {
	items := []RetestChange{{Change: ChangeNew}, {Change: ChangePersisting}, {Change: ChangePersisting}, {Change: ChangeRemediated}}
	want := "1 NEW, 2 PERSISTING, 1 REMEDIATED, 0 UNVERIFIED"
	if got := retestCounts(items); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
