package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainVerifiesAndDetectsTamper(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	l, _ := Open(p)
	l.Append("analyst", "request", "scan lab", nil)
	l.Append("agent", "plan", "2 steps", map[string]string{"n": "2"})
	l.Append("analyst:ayana", "approval", "approved S-01", nil)
	if err := l.Verify(); err != nil {
		t.Fatal(err)
	}
	l.Close()
	// Reload from disk: chain continues.
	l2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	l2.Append("agent", "done", "ok", nil)
	if err := l2.Verify(); err != nil {
		t.Fatal(err)
	}
	l2.Close()
	// Tamper with a recorded line.
	b, _ := os.ReadFile(p)
	bad := strings.Replace(string(b), "approved S-01", "approved S-99", 1)
	os.WriteFile(p, []byte(bad), 0o600)
	l3, _ := Open(p)
	defer l3.Close()
	if err := l3.Verify(); err == nil {
		t.Fatal("tampering was not detected")
	}
	// Deleting an entry is detected too.
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	os.WriteFile(p, []byte(strings.Join(append(lines[:1], lines[2:]...), "\n")+"\n"), 0o600)
	l4, _ := Open(p)
	defer l4.Close()
	if err := l4.Verify(); err == nil {
		t.Fatal("deletion was not detected")
	}
}
