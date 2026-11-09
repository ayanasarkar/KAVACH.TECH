package agent_test

import (
	"testing"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/adapters"
	"github.com/ayanasarkar/vapt-agent/internal/agent"
	"github.com/ayanasarkar/vapt-agent/internal/llm"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

func TestGap_DoubleStart(t *testing.T) {
	env := agent.Env{DataDir: t.TempDir(), Reg: adapters.NewRegistry(), LLM: llm.None{}}
	a, err := agent.New(env, "g1", "scan 127.0.0.1", scope.Scope{Authorization: "t", Targets: []string{"127.0.0.1"}, AllowActive: true}, []string{"127.0.0.1"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.Start()
	a.Start() // a double-click on "Start"
	time.Sleep(1500 * time.Millisecond)
	a.Lock()
	ph, n := a.Phase, 0
	for _, s := range a.Steps {
		if s.Status == "proposed" {
			n++
		}
	}
	a.Unlock()
	if n > 0 && ph != "awaiting_approval" {
		t.Errorf("STUCK: %d step(s) await approval but phase is %q, so ApprovePlan will refuse them", n, ph)
	}
}
