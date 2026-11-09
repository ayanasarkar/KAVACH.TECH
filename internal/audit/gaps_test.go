package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGap_TornLastLineBricksLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	l, _ := Open(p)
	for i := 0; i < 3; i++ {
		l.Append("system", "t", "x", nil)
	}
	l.Close()
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":4,"time":"2026-11-0`) // crash mid-write
	f.Close()
	l2, err := Open(p)
	if err != nil {
		t.Errorf("BRICKED: one half-written line (power loss/kill) makes the whole audit log unreadable: %v", err)
		return
	}
	es := l2.Entries()
	if len(es) != 4 || es[3].Type != "audit_recovered" {
		t.Errorf("want 3 intact entries + an audit_recovered record, got %d entries", len(es))
	}
	if err := l2.Verify(); err != nil {
		t.Errorf("chain must still verify after recovery: %v", err)
	}
	l2.Close()
	l3, err := Open(p) // the recovery itself must be durable
	if err != nil {
		t.Fatalf("reopen after recovery: %v", err)
	}
	defer l3.Close()

	if got := len(l3.Entries()); got != 4 {
		t.Errorf("reopen after recovery: got %d entries, want 4", got)
	}
}

func TestInfo_TruncationIsInvisible(t *testing.T) {
	l, _ := Open("")
	for i := 0; i < 6; i++ {
		l.Append("system", "t", "x", nil)
	}
	if err := VerifyEntries(l.Entries()[:3]); err == nil {
		t.Log("INFO: dropping the last 3 of 6 entries still verifies (expected for an unanchored chain)")
	}
}
