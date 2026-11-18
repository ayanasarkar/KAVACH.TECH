package adapters

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// Metasploit performs lab-only, human-approved validation using the module
// `check` action ONLY. It never runs `exploit`/`run`, never selects payloads,
// and is refused by the agent unless an analyst has approved the exact step.
type Metasploit struct{}

func (*Metasploit) Name() string     { return "metasploit" }
func (*Metasploit) Mode() Mode       { return Gated }
func (*Metasploit) Kind() scope.Kind { return scope.KindExploit }
func (*Metasploit) Describe() string {
	return "Approval-gated validation via msfconsole: runs a module's non-exploiting `check` only. Never autonomous."
}
func (*Metasploit) Available() (bool, string) { return have("msfconsole") }

var modRe = regexp.MustCompile(`^[a-z0-9_]+(/[a-z0-9_]+)+$`)

func (*Metasploit) Run(ctx context.Context, j Job) (Result, error) {
	mod := j.Options["module"]
	if !modRe.MatchString(mod) || !(strings.HasPrefix(mod, "auxiliary/scanner/") || strings.HasPrefix(mod, "exploit/")) {
		return Result{}, fmt.Errorf("module %q rejected: must be an auxiliary/scanner or exploit module path", mod)
	}
	if err := validHost(j.Host); err != nil {
		return Result{}, err
	}
	cmdline := fmt.Sprintf("use %s; set RHOSTS %s; ", mod, j.Host)
	if j.Port != 0 {
		if j.AllowPort != nil && !j.AllowPort(j.Port) {
			return Result{}, fmt.Errorf("port %d is not in the authorised port list", j.Port)
		}
		cmdline += fmt.Sprintf("set RPORT %d; ", j.Port)
	}
	cmdline += "check; exit"
	if ok, _ := have("msfconsole"); !ok {
		return msfMissingResult(j, mod), nil
	}
	out, errOut, err := runCmd(ctx, 4*time.Minute, "msfconsole", "-q", "-x", cmdline)
	res := Result{Raw: out + errOut}
	if err != nil {
		return res, err
	}
	v := classifyCheck(out)
	v.Module = mod
	res.Validation = v
	res.Summary = fmt.Sprintf("msf check %s on %s: %s", mod, j.Host, v.Verdict)
	return res, nil
}

// classifyCheck turns msfconsole `check` output into a verdict. It trusts only Metasploit's own check-result
// phrases and treats everything else as undetermined, because a wrong "not vulnerable" lowers confidence in a real
// finding and a wrong "vulnerable" confirms one that was never confirmed. Deliberately not matched: the bare word
// "safe" (it appears in unrelated lines such as "safe checks" or "unsafe"), and any line a module phrases in its own
// words. If vulnerable and not-vulnerable lines both appear, the output contradicts itself and the verdict is
// undetermined rather than whichever line came first.
func classifyCheck(out string) *Validation {
	v := &Validation{Verdict: "undetermined"}
	var pos, neg, note string
	for _, l := range strings.Split(out, "\n") {
		ll := strings.ToLower(strings.TrimSpace(l))
		switch {
		case strings.Contains(ll, "is not exploitable") || strings.Contains(ll, "is not vulnerable"):
			if neg == "" {
				neg = strings.TrimSpace(l)
			}
		case strings.Contains(ll, "appears to be vulnerable") || strings.Contains(ll, "is vulnerable"):
			if pos == "" {
				pos = strings.TrimSpace(l)
			}
		case strings.Contains(ll, "cannot reliably check") || strings.Contains(ll, "cannot be determined") ||
			strings.Contains(ll, "could not be validated") || strings.Contains(ll, "does not support check"):
			if note == "" {
				note = strings.TrimSpace(l)
			}
		}
	}
	switch {
	case pos != "" && neg != "":
		v.Line = "contradictory check output: " + pos + " | " + neg
	case pos != "":
		v.Verdict, v.Line = "vulnerable", pos
	case neg != "":
		v.Verdict, v.Line = "not_vulnerable", neg
	default:
		v.Line = note
	}
	return v
}
