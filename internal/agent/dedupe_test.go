package agent

import "testing"

func TestNormTarget(t *testing.T) {
	cases := map[string]string{
		"http://www.getvideo.org:80": "http://www.getvideo.org",
		"http://www.getvideo.org":    "http://www.getvideo.org",
		"HTTPS://Example.COM:443/":   "https://example.com",
		"http://127.0.0.1:8081":      "http://127.0.0.1:8081",
		"https://x.test:8443/a?b=1":  "https://x.test:8443/a?b=1",
		"http://[::1]:80/":           "http://[::1]",
		"http://host:443":            "http://host:443",
		"https://host:80":            "https://host:80",
		"127.0.0.1:2121":             "127.0.0.1:2121",
		"WWW.Example.org":            "www.example.org",
	}
	for in, want := range cases {
		if got := normTarget(in); got != want {
			t.Errorf("normTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSigTreatsDefaultPortAsSameEndpoint(t *testing.T) {
	a := sig("webcheck", "http://www.getvideo.org:80", nil, "")
	b := sig("webcheck", "http://www.getvideo.org", nil, "")
	if a != b {
		t.Errorf("the :80 spelling must be the same step as the bare URL:\n %q\n %q", a, b)
	}
	if sig("webcheck", "http://www.getvideo.org:8080", nil, "") == b {
		t.Error("a different port must stay a different step")
	}
	if sig("webcheck", "https://www.getvideo.org", nil, "") == b {
		t.Error("a different scheme must stay a different step")
	}
}

func TestRedundantPortscan(t *testing.T) {
	a := &Assessment{Steps: []Step{
		{ID: "S-01", Tool: "nmap", Target: "127.0.0.1", Status: "done"},
		{ID: "S-02", Tool: "nmap", Target: "10.0.0.9", Status: "failed"},
	}}
	cases := []struct {
		name      string
		p         proposal
		redundant bool
	}{
		{"portscan after nmap completed", proposal{Tool: "portscan", Target: "127.0.0.1"}, true},
		{"nmap failed, so portscan is a legitimate fallback", proposal{Tool: "portscan", Target: "10.0.0.9"}, false},
		{"host nmap never scanned", proposal{Tool: "portscan", Target: "192.168.1.5"}, false},
		{"other tools are unaffected", proposal{Tool: "webcheck", Target: "http://127.0.0.1:8081"}, false},
	}
	for _, c := range cases {
		if got := a.redundantStep(c.p) != ""; got != c.redundant {
			t.Errorf("%s: redundant=%v, want %v", c.name, got, c.redundant)
		}
	}
}
