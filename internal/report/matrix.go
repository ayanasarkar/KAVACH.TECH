// Package report builds the client-ready PDF and the integration matrix.
package report

import "github.com/ayanasarkar/vapt-agent/internal/adapters"

// Row is one line of the integration status matrix.
type Row struct {
	Tool        string `json:"tool"`
	Status      string `json:"status"` // Live | Import-only | Live (approval-gated)
	Method      string `json:"method"`
	Available   bool   `json:"available_now"`
	Note        string `json:"note"`
	Limitations string `json:"limitations"`
}

// Matrix returns the truthful integration status of the seven named tools plus
// the two built-in checkers, with live availability on this machine.
func Matrix(reg *adapters.Registry) []Row {
	rows := []struct{ name, tool, method, lim string }{
		{"nmap", "Nmap", "CLI (-sV, XML output)", "Requires the nmap binary on PATH; script (vulners) output is a version match only."},
		{"nessus", "Nessus", ".nessus v2 file import", "No live API integration; import only. Nessus is commercial (Essentials is capped at 16 hosts per Tenable docs): the analyst supplies a .nessus export from their own licence."},
		{"openvas", "OpenVAS / Greenbone", "XML report import", "No live GMP session yet (planned). Import accepts gvm-cli / web UI XML reports."},
		{"nikto", "Nikto", "CLI (XML output)", "Requires the nikto binary on PATH. Nikto does not rate severity; findings carry a nominal 'low'."},
		{"zap", "OWASP ZAP", "REST API (daemon)", "Requires a running ZAP daemon (ZAP_URL / ZAP_API_KEY). Active scan only if the scope allows it and the request asks for it."},
		{"burp", "Burp Suite", "XML issue export import", "No live integration; import only. PortSwigger documents a REST API for Burp Professional and a GraphQL API for Burp DAST, both under the analyst's own licence; this project never calls them."},
		{"metasploit", "Metasploit", "msfconsole `check` only, approval-gated", "Lab-only, never autonomous, never runs exploit/run or payloads. Requires msfconsole on PATH and an explicit human approval per run."},
		{"portscan", "Built-in port scan", "Go TCP connect + banner", "Not one of the seven named tools; fallback reconnaissance when Nmap is absent."},
		{"webcheck", "Built-in web checks", "Go read-only HTTP GET", "Not one of the seven named tools; read-only header, cookie, exposure checks."},
	}
	var out []Row
	for _, r := range rows {
		ad, ok := reg.Get(r.name)
		row := Row{Tool: r.tool, Method: r.method, Limitations: r.lim}
		if ok {
			row.Status = map[adapters.Mode]string{adapters.Live: "Live", adapters.ImportOnl: "Import-only", adapters.Gated: "Live (approval-gated)"}[ad.Mode()]
			row.Available, row.Note = ad.Available()
			if row.Available && row.Note == "" {
				row.Note = "available on this machine"
			}
		}
		out = append(out, row)
	}
	return out
}
