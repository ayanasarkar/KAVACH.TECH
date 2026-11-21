package main

import (
	"fmt"
	"io"
	"os"

	"github.com/ayanasarkar/vapt-agent/internal/audit"
	"github.com/ayanasarkar/vapt-agent/internal/report"
)

// runVerifyAudit is the offline `vapt -verify-audit <dir>` command. It needs no console, no network and no model:
// it recomputes the hash chain from <dir>/audit.jsonl, re-hashes every raw tool output under <dir>/raw against the
// digest sealed in that chain, and, when a SARIF file is given, checks that export is bound to the same chain.
// It reads only and returns the process exit code: 0 verified, 1 not verified, 2 could not run.
func runVerifyAudit(dir, sarifPath string, w io.Writer) int {
	rep, err := audit.VerifyDir(dir)
	if err != nil {
		fmt.Fprintf(w, "KAVACH audit verification: %s\n  cannot read the audit log: %v\n", dir, err)
		return 2
	}
	fmt.Fprintf(w, "KAVACH audit verification: %s\n", dir)
	ok := rep.OK()

	if rep.ChainErr != nil {
		fmt.Fprintf(w, "  hash chain   : FAILED - %v\n", rep.ChainErr)
	} else {
		fmt.Fprintf(w, "  hash chain   : OK - %d entries, head %s\n", len(rep.Entries), rep.Head)
	}

	if len(rep.Raw) == 0 {
		fmt.Fprintf(w, "  raw evidence : none sealed in the chain\n")
	} else if n := rep.RawOK(); n == len(rep.Raw) {
		fmt.Fprintf(w, "  raw evidence : OK - %d of %d raw files match the digests sealed in the chain\n", n, len(rep.Raw))
	} else {
		fmt.Fprintf(w, "  raw evidence : FAILED - %d of %d raw files match\n", n, len(rep.Raw))
		for _, c := range rep.Raw {
			switch c.Status {
			case "mismatch":
				fmt.Fprintf(w, "    MISMATCH %s (%s)\n      sealed   %s\n      on disk  %s\n", c.File, c.Step, c.Sealed, c.OnDisk)
			case "missing":
				fmt.Fprintf(w, "    MISSING  %s (%s)\n      sealed   %s\n", c.File, c.Step, c.Sealed)
			}
		}
	}
	for _, f := range rep.Unsealed {
		fmt.Fprintf(w, "  note         : %s is not sealed by any run_end entry (not covered by this check)\n", f)
	}

	if sarifPath != "" {
		b, err := os.ReadFile(sarifPath)
		if err != nil {
			fmt.Fprintf(w, "  SARIF        : FAILED - %v\n", err)
			ok = false
		} else if msg, err := report.CheckSARIF(b, rep.Entries, rep.Sealed); err != nil {
			fmt.Fprintf(w, "  SARIF        : FAILED - %v\n", err)
			ok = false
		} else {
			fmt.Fprintf(w, "  SARIF        : OK - %s\n", msg)
		}
	}

	if ok {
		fmt.Fprintln(w, "RESULT: VERIFIED")
		return 0
	}
	fmt.Fprintln(w, "RESULT: NOT VERIFIED - the evidence does not match its audit record")
	return 1
}
