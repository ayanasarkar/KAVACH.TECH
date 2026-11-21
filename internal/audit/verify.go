package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Sealed is the raw-output digest that one run_end entry committed to the chain.
type Sealed struct {
	Step   string
	SHA256 string
	Seq    int // chain entry that sealed it
}

// RawCheck is the verdict for one sealed raw file.
type RawCheck struct {
	Step   string
	File   string // slash-separated, relative to the assessment directory, e.g. raw/S-02-webcheck.txt
	Sealed string // digest recorded in the chain
	OnDisk string // digest of the file now ("" when it is missing)
	Status string // ok | mismatch | missing
}

// DirReport is the outcome of verifying an assessment directory offline.
type DirReport struct {
	Entries  []Entry
	Head     string // hash of the last intact entry
	ChainErr error  // nil when every entry parsed and the hash chain recomputes
	Raw      []RawCheck
	Sealed   map[string]Sealed // step id -> sealed digest
	Unsealed []string          // raw files no run_end entry vouches for (reported, not a failure)
}

// RawOK counts the raw files whose digest matches the sealed one.
func (r DirReport) RawOK() int {
	n := 0
	for _, c := range r.Raw {
		if c.Status == "ok" {
			n++
		}
	}
	return n
}

// OK is true only when the chain recomputes and every sealed raw file matches its digest.
func (r DirReport) OK() bool { return r.ChainErr == nil && r.RawOK() == len(r.Raw) }

// VerifyDir verifies <dir>/audit.jsonl and <dir>/raw offline. It only reads. Unlike Open it never repairs or
// truncates a damaged tail: a half-written record is reported as a chain failure and the file is left as found.
func VerifyDir(dir string) (DirReport, error) {
	rep := DirReport{Sealed: map[string]Sealed{}}
	b, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		return rep, err
	}
	for i, ln := range bytes.Split(b, []byte("\n")) {
		t := bytes.TrimSpace(ln)
		if len(t) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(t, &e); err != nil {
			rep.ChainErr = fmt.Errorf("line %d is not a complete audit entry (damaged or partly written): %v", i+1, err)
			break
		}
		rep.Entries = append(rep.Entries, e)
	}
	if len(rep.Entries) == 0 {
		return rep, errors.New("audit log holds no entries")
	}
	rep.Head = rep.Entries[len(rep.Entries)-1].Hash
	if rep.ChainErr == nil {
		rep.ChainErr = VerifyEntries(rep.Entries)
	}

	covered := map[string]bool{}
	for _, e := range rep.Entries {
		sum := e.Detail["sha256"]
		step := e.Detail["step"]
		if e.Type != "run_end" || sum == "" || step == "" || !strings.HasPrefix(e.Actor, "tool:") {
			continue
		}
		if _, dup := rep.Sealed[step]; dup {
			continue
		}
		rep.Sealed[step] = Sealed{Step: step, SHA256: sum, Seq: e.Seq}
		name := fmt.Sprintf("%s-%s.txt", step, strings.TrimPrefix(e.Actor, "tool:"))
		c := RawCheck{Step: step, File: "raw/" + name, Sealed: sum}
		covered[name] = true
		if filepath.Base(name) != name { // a tampered step or tool name must not walk out of raw/
			c.Status = "missing"
			rep.Raw = append(rep.Raw, c)
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "raw", name))
		switch {
		case err != nil:
			c.Status = "missing"
		default:
			h := sha256.Sum256(data)
			c.OnDisk = hex.EncodeToString(h[:])
			if strings.EqualFold(c.OnDisk, sum) {
				c.Status = "ok"
			} else {
				c.Status = "mismatch"
			}
		}
		rep.Raw = append(rep.Raw, c)
	}

	if ents, err := os.ReadDir(filepath.Join(dir, "raw")); err == nil {
		for _, de := range ents {
			if !de.IsDir() && !covered[de.Name()] {
				rep.Unsealed = append(rep.Unsealed, "raw/"+de.Name())
			}
		}
		sort.Strings(rep.Unsealed)
	}
	return rep, nil
}
