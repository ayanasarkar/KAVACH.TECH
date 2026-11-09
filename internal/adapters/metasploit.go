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
	out, errOut, err := runCmd(ctx, 4*time.Minute, "msfconsole", "-q", "-x", cmdline)
	res := Result{Raw: out + errOut}
	if err != nil {
		return res, err
	}
	v := &Validation{Verdict: "undetermined", Module: mod}
	for _, l := range strings.Split(out, "\n") {
		ll := strings.ToLower(l)
		switch {
		case strings.Contains(ll, "appears to be vulnerable") || strings.Contains(ll, "is vulnerable"):
			v.Verdict, v.Line = "vulnerable", strings.TrimSpace(l)
		case strings.Contains(ll, "not exploitable") || strings.Contains(ll, "is not vulnerable") || strings.Contains(ll, "safe"):
			if v.Verdict != "vulnerable" {
				v.Verdict, v.Line = "not_vulnerable", strings.TrimSpace(l)
			}
		case strings.Contains(ll, "cannot reliably check") || strings.Contains(ll, "cannot be determined"):
			if v.Line == "" {
				v.Line = strings.TrimSpace(l)
			}
		}
	}
	res.Validation = v
	res.Summary = fmt.Sprintf("msf check %s on %s: %s", mod, j.Host, v.Verdict)
	return res, nil
}
