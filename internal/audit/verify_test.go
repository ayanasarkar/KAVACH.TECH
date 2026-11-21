package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture writes an assessment directory the way the agent does: raw files plus a chain that seals their digests.
func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "raw"), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Append("analyst", "request", "assess the lab", nil)
	for _, s := range []struct{ id, tool, body string }{
		{"S-01", "nmap", "22/tcp open ssh\n80/tcp open http\n"},
		{"S-02", "webcheck", "GET /.git/HEAD -> 200\nref: refs/heads/master\n"},
	} {
		if err := os.WriteFile(filepath.Join(dir, "raw", s.id+"-"+s.tool+".txt"), []byte(s.body), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(s.body))
		l.Append("tool:"+s.tool, "run_end", s.id+" done", map[string]string{"step": s.id, "status": "done", "sha256": hex.EncodeToString(sum[:])})
	}
	return dir
}

func TestVerifyDirIntact(t *testing.T) {
	rep, err := VerifyDir(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.ChainErr != nil || len(rep.Raw) != 2 || rep.RawOK() != 2 || len(rep.Entries) != 3 {
		t.Fatalf("intact directory must verify: %+v", rep)
	}
	if rep.Head != rep.Entries[2].Hash || rep.Head == "" {
		t.Errorf("head = %q", rep.Head)
	}
	if len(rep.Unsealed) != 0 {
		t.Errorf("unexpected unsealed files: %v", rep.Unsealed)
	}
}

func TestVerifyDirDetectsOneFlippedByteInRawEvidence(t *testing.T) {
	dir := fixture(t)
	p := filepath.Join(dir, "raw", "S-02-webcheck.txt")
	b, _ := os.ReadFile(p)
	b[5] ^= 0x01
	os.WriteFile(p, b, 0o600)
	rep, _ := VerifyDir(dir)
	if rep.OK() || rep.ChainErr != nil || rep.RawOK() != 1 {
		t.Fatalf("tampered raw file must fail while the chain itself stays intact: %+v", rep)
	}
	var bad RawCheck
	for _, c := range rep.Raw {
		if c.Status != "ok" {
			bad = c
		}
	}
	if bad.Step != "S-02" || bad.Status != "mismatch" || bad.OnDisk == bad.Sealed || bad.OnDisk == "" {
		t.Errorf("wrong verdict: %+v", bad)
	}
}

func TestVerifyDirDetectsMissingRawFile(t *testing.T) {
	dir := fixture(t)
	os.Remove(filepath.Join(dir, "raw", "S-01-nmap.txt"))
	rep, _ := VerifyDir(dir)
	if rep.OK() || rep.Raw[0].Status != "missing" {
		t.Fatalf("a deleted raw file must fail verification: %+v", rep.Raw)
	}
}

func TestVerifyDirDetectsEditedChainEntry(t *testing.T) {
	dir := fixture(t)
	p := filepath.Join(dir, "audit.jsonl")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), "assess the lab", "assess the bank", 1)), 0o600)
	rep, _ := VerifyDir(dir)
	if rep.OK() || rep.ChainErr == nil || !strings.Contains(rep.ChainErr.Error(), "altered") {
		t.Fatalf("an edited entry must break the chain: %v", rep.ChainErr)
	}
}

// Verification only reads. A half-written tail is reported, never repaired or truncated the way Open does.
func TestVerifyDirNeverModifiesTheLog(t *testing.T) {
	dir := fixture(t)
	p := filepath.Join(dir, "audit.jsonl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":4,"time":"2026`)
	f.Close()
	before, _ := os.ReadFile(p)
	rep, err := VerifyDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || rep.ChainErr == nil {
		t.Error("a damaged tail must be reported as a failure")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Error("VerifyDir modified the audit log")
	}
}

func TestVerifyDirReportsUnsealedRawFile(t *testing.T) {
	dir := fixture(t)
	os.WriteFile(filepath.Join(dir, "raw", "S-09-extra.txt"), []byte("x"), 0o600)
	rep, _ := VerifyDir(dir)
	if !rep.OK() || len(rep.Unsealed) != 1 || rep.Unsealed[0] != "raw/S-09-extra.txt" {
		t.Errorf("unsealed file should be noted but not fail the check: %+v", rep)
	}
}

func TestVerifyDirNoLog(t *testing.T) {
	if _, err := VerifyDir(t.TempDir()); err == nil {
		t.Error("a directory with no audit log must be an error, not a pass")
	}
}

func TestVerifyDirRefusesPathTraversalInStepName(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "raw"), 0o700)
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("x"), 0o600)
	l, _ := Open(filepath.Join(dir, "audit.jsonl"))
	sum := sha256.Sum256([]byte("x"))
	l.Append("tool:../x", "run_end", "evil", map[string]string{"step": "..", "sha256": hex.EncodeToString(sum[:])})
	l.Close()
	rep, _ := VerifyDir(dir)
	if rep.OK() {
		t.Errorf("a step name that escapes raw/ must not verify: %+v", rep.Raw)
	}
}
