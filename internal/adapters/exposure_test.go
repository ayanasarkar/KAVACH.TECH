package adapters

import (
	"testing"

	"github.com/ayanasarkar/vapt-agent/internal/model"
)

// Telnet, FTP and exposed data services must be reported the same way whichever scanner saw them.
func TestExposureFindingSameForBothScanners(t *testing.T) {
	cases := []struct{ name, key, sev string }{
		{"telnet", "net:cleartext:telnet", "high"},
		{"ftp", "net:cleartext:ftp", "medium"},
		{"mysql", "net:exposed-datastore:mysql", "medium"},
		{"redis", "net:exposed-datastore:redis", "medium"},
	}
	for _, c := range cases {
		svc := model.Service{Host: "10.0.0.5", Port: 4242, Proto: "tcp", State: "open", Name: c.name}
		a, okA := exposureFinding("nmap", svc, "x", "line 1")
		b, okB := exposureFinding("portscan", svc, "x", "line 1")
		if !okA || !okB {
			t.Fatalf("%s: no finding (nmap=%v portscan=%v)", c.name, okA, okB)
		}
		if a.Key != c.key || a.Severity != c.sev || a.Title != b.Title || a.Key != b.Key || a.Tool != "nmap" || b.Tool != "portscan" {
			t.Errorf("%s: mismatch: %+v vs %+v", c.name, a, b)
		}
	}
	for _, n := range []string{"http", "https", "ssh", "smtp", "msrpc", ""} {
		if _, ok := exposureFinding("nmap", model.Service{Name: n, State: "open"}, "", ""); ok {
			t.Errorf("%q must not raise an exposure finding", n)
		}
	}
}
