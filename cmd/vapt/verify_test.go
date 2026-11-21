package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ayanasarkar/vapt-agent/internal/audit"
	"github.com/ayanasarkar/vapt-agent/internal/report"
)

func assessmentDir(t *testing.T, note string) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "raw"), 0o700)
	l, err := audit.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Append("analyst", "request", note, nil)
	body := "GET /.git/HEAD -> 200\n"
	os.WriteFile(filepath.Join(dir, "raw", "S-01-webcheck.txt"), []byte(body), 0o600)
	h := sha256.Sum256([]byte(body))
	l.Append("tool:webcheck", "run_end", "S-01 done", map[string]string{"step": "S-01", "status": "done", "sha256": hex.EncodeToString(h[:])})
	return dir
}

func boundSARIF(t *testing.T, dir string) string {
	t.Helper()
	rep, err := audit.VerifyDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	ab := report.AuditBinding{HeadHash: rep.Head, Entries: len(rep.Entries), Status: "verified"}
	for _, s := range rep.Sealed {
		ab.Raw = append(ab.Raw, report.RawDigest{Step: s.Step, File: "raw/" + s.Step + "-webcheck.txt", SHA256: s.SHA256})
	}
	b, err := report.SARIFWithAudit("A-1", nil, ab)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "x.sarif")
	os.WriteFile(p, b, 0o644)
	return p
}

func TestVerifyAuditExitCodes(t *testing.T) {
	dir := assessmentDir(t, "assess the lab")
	var out bytes.Buffer
	if code := runVerifyAudit(dir, "", &out); code != 0 || !strings.Contains(out.String(), "RESULT: VERIFIED") {
		t.Fatalf("intact dir: code %d\n%s", code, out.String())
	}

	// one flipped byte in a raw file: exit 1, and the output names the file
	p := filepath.Join(dir, "raw", "S-01-webcheck.txt")
	b, _ := os.ReadFile(p)
	b[0] ^= 1
	os.WriteFile(p, b, 0o600)
	out.Reset()
	if code := runVerifyAudit(dir, "", &out); code != 1 || !strings.Contains(out.String(), "MISMATCH raw/S-01-webcheck.txt") || !strings.Contains(out.String(), "NOT VERIFIED") {
		t.Fatalf("tampered raw: code %d\n%s", code, out.String())
	}

	// nothing to verify: exit 2, never a pass
	out.Reset()
	if code := runVerifyAudit(t.TempDir(), "", &out); code != 2 {
		t.Fatalf("empty dir must be exit 2, got %d\n%s", code, out.String())
	}
}

func TestVerifyAuditChecksSARIFBinding(t *testing.T) {
	dir := assessmentDir(t, "assess the lab")
	sar := boundSARIF(t, dir)
	var out bytes.Buffer
	if code := runVerifyAudit(dir, sar, &out); code != 0 || !strings.Contains(out.String(), "SARIF        : OK") {
		t.Fatalf("matching SARIF: code %d\n%s", code, out.String())
	}
	// the same SARIF checked against a different assessment's chain must fail
	other := assessmentDir(t, "assess a different host")
	out.Reset()
	if code := runVerifyAudit(other, sar, &out); code != 1 || !strings.Contains(out.String(), "SARIF        : FAILED") {
		t.Fatalf("SARIF from another chain: code %d\n%s", code, out.String())
	}
	// a SARIF path that does not exist is a failure, not a skip
	out.Reset()
	if code := runVerifyAudit(dir, filepath.Join(t.TempDir(), "nope.sarif"), &out); code != 1 {
		t.Fatalf("missing SARIF file must fail, got %d", code)
	}
}
