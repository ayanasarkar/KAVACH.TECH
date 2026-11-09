// Package audit is an append-only, hash-chained decision log. Every entry's
// hash covers the previous hash, so edits or deletions are detectable.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry is one audited event.
type Entry struct {
	Seq      int               `json:"seq"`
	Time     time.Time         `json:"time"`
	Actor    string            `json:"actor"` // analyst | agent | scope-guard | tool:<name> | system
	Type     string            `json:"type"`  // request, plan, scope_decision, run_start, run_end, approval, ...
	Summary  string            `json:"summary"`
	Detail   map[string]string `json:"detail,omitempty"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

// Log is the chained log.
type Log struct {
	mu      sync.Mutex
	entries []Entry
	f       *os.File
	werr    error // first write/sync failure; the in-memory chain is then ahead of the file
}

// Err returns the first failure to persist an entry (nil if every entry reached the disk).
func (l *Log) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.werr
}

// Open opens (creating if needed) a log file and loads existing entries.
func Open(path string) (*Log, error) {
	l := &Log{}
	if path == "" {
		return l, nil
	}
	recovered := 0
	if b, err := os.ReadFile(path); err == nil {
		lines := bytes.SplitAfter(b, []byte("\n"))
		off := 0
		for i, ln := range lines {
			t := bytes.TrimSpace(ln)
			if len(t) == 0 {
				off += len(ln)
				continue
			}
			var e Entry
			if err := json.Unmarshal(t, &e); err != nil {
				// A half-written FINAL record (crash, power loss, kill) is recoverable: drop it and
				// truncate so the chain continues from the last good entry. Corruption anywhere else is
				// not recoverable and is reported.
				if len(bytes.TrimSpace(bytes.Join(lines[i+1:], nil))) == 0 {
					recovered = len(ln)
					if terr := os.Truncate(path, int64(off)); terr != nil {
						return nil, terr
					}
					break
				}
				return nil, fmt.Errorf("corrupt audit log at line %d: %w", i+1, err)
			}
			l.entries = append(l.entries, e)
			off += len(ln)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	if recovered > 0 {
		l.Append("system", "audit_recovered", fmt.Sprintf("discarded %d bytes of a partially written final record after an unclean shutdown; chain continues from the last intact entry", recovered), nil)
	}
	return l, nil
}

func hashOf(e Entry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Append records an event and returns it.
func (l *Log) Append(actor, typ, summary string, detail map[string]string) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{Seq: len(l.entries) + 1, Time: time.Now().UTC(), Actor: actor, Type: typ, Summary: summary, Detail: detail}
	if n := len(l.entries); n > 0 {
		e.PrevHash = l.entries[n-1].Hash
	}
	e.Hash = hashOf(e)
	l.entries = append(l.entries, e)
	if l.f != nil {
		b, err := json.Marshal(e)
		if err == nil {
			if _, err = l.f.Write(append(b, '\n')); err == nil {
				err = l.f.Sync()
			}
		}
		if err != nil && l.werr == nil {
			l.werr = err
		}
	}
	return e
}

// Entries returns a copy of all entries.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Entry(nil), l.entries...)
}

// Verify re-computes the chain.
func (l *Log) Verify() error { return VerifyEntries(l.Entries()) }

// VerifyEntries checks a slice of entries.
func VerifyEntries(es []Entry) error {
	prev := ""
	for i, e := range es {
		if e.Seq != i+1 {
			return fmt.Errorf("entry %d: sequence gap", i+1)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("entry %d: chain broken", e.Seq)
		}
		if hashOf(e) != e.Hash {
			return fmt.Errorf("entry %d: content altered", e.Seq)
		}
		prev = e.Hash
	}
	return nil
}

// Close closes the backing file. It is safe to call more than once.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.f == nil {
		return nil
	}

	err := l.f.Close()
	l.f = nil
	return err
}
