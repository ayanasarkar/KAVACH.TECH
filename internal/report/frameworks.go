package report

import (
	"sort"
	"strings"
)

// cweFramework is what a CWE is aligned to for the report, at the level this project
// can actually stand behind:
//
//   - csfCat / csfName: a NIST CSF 2.0 Protect-function CATEGORY (e.g. "PR.DS"), not a
//     sub-category. Category codes and their meaning are stable and independently
//     documented; the specific sub-category outcome text (PR.DS-01, PR.DS-02, ...)
//     is not reproduced here because it could not be confirmed against the primary
//     text at the precision this report wants to claim.
//   - tacticID / tacticName: a MITRE ATT&CK Enterprise TACTIC (one of the 14 stable,
//     well-known tactics, e.g. "TA0043 Reconnaissance" ), not a specific technique ID.
//     MITRE does not publish a direct CWE-to-ATT&CK table; the real bridge runs
//     CWE -> CAPEC -> ATT&CK, and a single CWE routinely links to dozens of CAPEC
//     entries (CWE-200 alone lists 59), so picking one "the" technique per CWE would
//     overstate precision this project has not verified. The tactic a weakness would
//     most plausibly help an attacker reach is a defensible, checkable claim; a
//     specific technique ID is not, without that deeper CAPEC-level research.
//   - why: one sentence a judge can be given as the reasoning, so the mapping is an
//     argument that can be checked, not a bare lookup.
//
// This is deliberately a narrower claim than "CWE X is ATT&CK technique Y" or "is CSF
// control Z": see the disclaimer this package attaches wherever it renders (matching
// the hackathon's own problem statement: "Using these standards and frameworks does
// not, by itself, establish formal compliance with them").
type cweFramework struct {
	csfCat, csfName      string
	tacticID, tacticName string
	why                  string
}

// frameworkByCWE covers every CWE this codebase's adapters currently assign
// (internal/adapters/{portscan,webcheck,zap}.go). Keep it in sync with them:
// TestFrameworkCoversEveryAdapterCWE in frameworks_test.go fails if a new CWE id is
// introduced there without an entry here.
var frameworkByCWE = map[string]cweFramework{
	"CWE-200": {"PR.DS", "Data Security", "TA0043", "Reconnaissance",
		"information exposed to an unauthorised actor is reconnaissance material for an attacker, not yet an intrusion."},
	"CWE-319": {"PR.DS", "Data Security", "TA0006", "Credential Access",
		"sensitive data sent in cleartext can be read by anyone positioned on the path, including credentials."},
	"CWE-284": {"PR.AA", "Identity Management, Authentication and Access Control", "TA0001", "Initial Access",
		"an access-control boundary that is not correctly enforced is how an attacker gets in without valid credentials."},
	"CWE-693": {"PR.PS", "Platform Security", "TA0001", "Initial Access",
		"a missing browser-enforced protection (CSP, MIME sniffing) is what lets a crafted page or response reach a victim's browser as if trusted."},
	"CWE-1021": {"PR.PS", "Platform Security", "TA0001", "Initial Access",
		"without clickjacking protection, a victim can be tricked into an action on the real site from inside an attacker's page."},
	"CWE-1004": {"PR.DS", "Data Security", "TA0006", "Credential Access",
		"a session cookie without HttpOnly can be read by any script that runs on the page, including an injected one."},
	"CWE-614": {"PR.DS", "Data Security", "TA0006", "Credential Access",
		"a session cookie without Secure can be sent over a downgraded or intercepted connection."},
	"CWE-548": {"PR.PS", "Platform Security", "TA0043", "Reconnaissance",
		"a directory listing hands an attacker the site's real file layout for free."},
	"CWE-527": {"PR.PS", "Platform Security", "TA0043", "Reconnaissance",
		"an exposed .git directory discloses source and history; if any secret ever entered that history, this becomes Credential Access (TA0006)."},
	"CWE-538": {"PR.DS", "Data Security", "TA0006", "Credential Access",
		"a reachable .env or similar file typically contains live credentials, not just configuration."},
}

// frameworkLine renders the distinct framework alignments for a finding's CWEs, e.g.
// "MITRE ATT&CK: Reconnaissance (TA0043); NIST CSF 2.0: PR.PS Platform Security." It
// returns "" if none of the finding's CWEs (or the finding has none) are in the table,
// so a finding with an unmapped or absent CWE simply omits the line rather than show a
// blank or placeholder one.
func frameworkLine(cwes []string) string {
	tactics := map[string]string{} // id -> name
	cats := map[string]string{}    // code -> name
	for _, cwe := range cwes {
		fw, ok := frameworkByCWE[strings.ToUpper(strings.TrimSpace(cwe))]
		if !ok {
			continue
		}
		tactics[fw.tacticID] = fw.tacticName
		cats[fw.csfCat] = fw.csfName
	}
	if len(tactics) == 0 && len(cats) == 0 {
		return ""
	}
	var tk, ck []string
	for id := range tactics {
		tk = append(tk, id)
	}
	for c := range cats {
		ck = append(ck, c)
	}
	sort.Strings(tk)
	sort.Strings(ck)
	var tp, cp []string
	for _, id := range tk {
		tp = append(tp, tactics[id]+" ("+id+")")
	}
	for _, c := range ck {
		cp = append(cp, c+" "+cats[c])
	}
	out := ""
	if len(tp) > 0 {
		out += "MITRE ATT&CK: " + strings.Join(tp, ", ")
	}
	if len(cp) > 0 {
		if out != "" {
			out += "    "
		}
		out += "NIST CSF 2.0: " + strings.Join(cp, ", ")
	}
	return out
}

// frameworkLists is frameworkLine's data in structured form, for machine-readable exports: the distinct MITRE
// ATT&CK tactics ("TA0043 Reconnaissance") and NIST CSF 2.0 categories ("PR.PS Platform Security") for a finding's
// CWEs, each sorted. Same table, same precision as the PDF; nothing is added that the PDF does not already claim.
func frameworkLists(cwes []string) (tactics, csf []string) {
	t := map[string]string{}
	c := map[string]string{}
	for _, cwe := range cwes {
		if fw, ok := frameworkByCWE[strings.ToUpper(strings.TrimSpace(cwe))]; ok {
			t[fw.tacticID] = fw.tacticName
			c[fw.csfCat] = fw.csfName
		}
	}
	for id, n := range t {
		tactics = append(tactics, id+" "+n)
	}
	for id, n := range c {
		csf = append(csf, id+" "+n)
	}
	sort.Strings(tactics)
	sort.Strings(csf)
	return tactics, csf
}
