package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ayanasarkar/vapt-agent/internal/adapters"
	"github.com/ayanasarkar/vapt-agent/internal/audit"
	"github.com/ayanasarkar/vapt-agent/internal/llm"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

func restoreEnv(t *testing.T) Env {
	t.Helper()
	return Env{DataDir: t.TempDir(), Reg: adapters.NewRegistry(), LLM: llm.FromEnv()}
}

func restoreScope() scope.Scope {
	return scope.Scope{Name: "lab", Authorization: "unit test", Targets: []string{"127.0.0.1"}, AllowActive: true}
}

func TestRestoreKeepsDataAndAuditChain(t *testing.T) {
	env := restoreEnv(t)
	a, err := New(env, "20261101-101010-abcd", "review the lab", restoreScope(), []string{"127.0.0.1"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	a.Phase = "review"
	a.Limitations = append(a.Limitations, "kept")
	a.event("info", "saved before restart")
	before, _ := a.AuditEntries()
	a.Close()

	got, err := Restore(env, filepath.Join(env.DataDir, "20261101-101010-abcd"))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if got.Request != "review the lab" || got.Phase != "review" || len(got.Limitations) != 1 {
		t.Fatalf("saved fields were not restored: %+v", got.Phase)
	}
	if got.Guard() == nil {
		t.Fatal("scope guard was not rebuilt")
	}
	after, _ := got.AuditEntries()
	if len(after) != len(before) {
		t.Fatalf("audit entries changed on restore: %d before, %d after", len(before), len(after))
	}
	got.audit("analyst", "test", "after restart", nil)
	more, _ := got.AuditEntries()
	if len(more) != len(before)+1 {
		t.Fatalf("new entry not appended: %d entries, want %d", len(more), len(before)+1)
	}
	if err := audit.VerifyEntries(more); err != nil {
		t.Fatalf("audit chain broke after restart: %v", err)
	}
}

func TestRestoreMarksInterruptedRun(t *testing.T) {
	env := restoreEnv(t)
	a, err := New(env, "20261102-101010-abcd", "scan", restoreScope(), []string{"127.0.0.1"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	a.Phase = "running"
	a.Steps = []Step{{ID: "S-01", Status: "running"}, {ID: "S-02", Status: "done"}}
	a.Save()
	a.Close()

	got, err := Restore(env, filepath.Join(env.DataDir, a.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if got.Phase != "review" {
		t.Fatalf("phase = %q, want review", got.Phase)
	}
	if got.Steps[0].Status != "failed" || got.Steps[1].Status != "done" {
		t.Fatalf("step statuses = %q, %q", got.Steps[0].Status, got.Steps[1].Status)
	}
	if len(got.Limitations) == 0 {
		t.Fatal("no interruption note recorded")
	}
}

func TestRestoreAllSkipsOtherFolders(t *testing.T) {
	env := restoreEnv(t)
	os.MkdirAll(filepath.Join(env.DataDir, "auth"), 0o700)
	a, err := New(env, "20261103-101010-abcd", "scan", restoreScope(), []string{"127.0.0.1"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	a.Save()
	a.Close()
	got, problems := RestoreAll(env)
	if len(got) != 1 || len(problems) != 0 {
		t.Fatalf("restored %d, problems %v", len(got), problems)
	}
	got[0].Close()
}
