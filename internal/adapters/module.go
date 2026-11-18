package adapters

import (
	"fmt"
	"strings"
)

// ValidModule reports whether mod is a module path the Metasploit adapter will run. The agent calls it when a
// validation is requested, so a blank or malformed module is refused at once, before anyone has approved it.
func ValidModule(mod string) error {
	if strings.TrimSpace(mod) == "" {
		return fmt.Errorf("enter a Metasploit module path, for example auxiliary/scanner/telnet/telnet_version")
	}
	if !modRe.MatchString(mod) || !(strings.HasPrefix(mod, "auxiliary/scanner/") || strings.HasPrefix(mod, "exploit/")) {
		return fmt.Errorf("module %q rejected: must be an auxiliary/scanner or exploit module path, for example auxiliary/scanner/telnet/telnet_version", mod)
	}
	return nil
}

// msfMissingResult is what an approved validation records when msfconsole is not installed. It runs nothing and
// claims nothing: the verdict is undetermined and the line says why.
func msfMissingResult(j Job, mod string) Result {
	line := fmt.Sprintf("msfconsole is not installed on this machine, so the check for %s on %s was not run.", mod, j.Host)
	return Result{
		Raw:        "[KAVACH] " + line + " No packets were sent by this step.\n",
		Summary:    fmt.Sprintf("msf check %s on %s: undetermined (msfconsole not installed)", mod, j.Host),
		Validation: &Validation{Verdict: "undetermined", Module: mod, Line: line},
	}
}
