package agent

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// Everything a target sends back (banners, HTTP headers, tool output) is data,
// never instructions. These rules spot text that tries to command the agent so it
// can be withheld from model prompts, kept out of the CVE grounding check, and audited.
var injectionRules = []struct {
	name string
	re   *regexp.Regexp
}{
	{"override-instructions", regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(rules?|instructions?|guard|scope|polic(y|ies)|previous|prior)\b`)},
	{"role-change", regexp.MustCompile(`(?i)\b(you are now|new instructions?|system prompt|pretend to be)\b`)},
	{"command-to-agent", regexp.MustCompile(`(?i)\b(scan|attack|exploit|probe)\s+(\d{1,3}(\.\d{1,3}){3}|[a-z0-9-]+(\.[a-z0-9-]+)+)`)},
	{"fabricated-finding", regexp.MustCompile(`(?i)\b(report|record|add|flag)\b[^.\n]{0,24}\bCVE-\d{4}-\d{4,}`)},
}

// injIPRe finds bare IPv4 addresses named inside hostile text (planner.go's ipRe also
// accepts a :port suffix, which is not wanted here).
var injIPRe = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// withheld replaces instruction-like target text wherever a model could read it.
const withheld = "[withheld: instruction-like text from target]"

// detectInjection reports the first rule that matches instruction-like text.
func detectInjection(s string) (string, bool) {
	for _, r := range injectionRules {
		if r.re.MatchString(s) {
			return r.name, true
		}
	}
	return "", false
}

// safeText is what a model may see of untrusted target text.
func safeText(s string) string {
	if _, bad := detectInjection(s); bad {
		return withheld
	}
	return s
}

// flagInjection audits instruction-like text found in target-controlled data. The
// evidence itself is kept verbatim; only model-facing views are sanitised. Each
// distinct (asset, rule) is recorded once: the same hostile text echoed in another
// field (a banner repeated in a tool's finding text) is the same incident.
func (a *Assessment) flagInjection(host string, port int, tool, field, text string) {
	rule, bad := detectInjection(text)
	if !bad {
		return
	}
	key := fmt.Sprintf("%s:%d|%s", host, port, rule)
	if a.injSeen == nil {
		a.injSeen = map[string]bool{}
	}
	if a.injSeen[key] {
		return
	}
	a.injSeen[key] = true
	var named []string
	seen := map[string]bool{}
	for _, ip := range injIPRe.FindAllString(text, -1) {
		if seen[ip] || ip == host { // the asset's own address (e.g. in a tool's output prefix) was not "named" by the text
			continue
		}
		seen[ip] = true
		if d := a.guard.Check(scope.Action{Tool: "agent", Target: ip, Kind: scope.KindPassive}); d.Allowed {
			named = append(named, ip+": inside scope, but target text is data and was not acted on")
		} else {
			named = append(named, ip+": REFUSED by the scope guard ("+d.Reason+")")
		}
	}
	sum := fmt.Sprintf("[PROMPT-INJECTION BLOCKED] %s:%d %s tried to instruct the agent (%s).", host, port, field, rule)
	d := map[string]string{"host": host, "port": strconv.Itoa(port), "tool": tool, "field": field, "rule": rule,
		"excerpt": clipS(text, 160), "action": "withheld from model prompts and not used as grounding; nothing was planned from it"}
	msg := sum + " Treated as data: withheld from model prompts, not used as grounding, nothing planned from it."
	if len(named) > 0 {
		d["named_targets"] = strings.Join(named, "; ")
		msg += " Targets it named: " + strings.Join(named, "; ") + "."
	}
	a.audit("agent", "prompt_injection_blocked", sum, d)
	a.event("warn", msg)
}
