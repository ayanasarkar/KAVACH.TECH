package scope

import (
	"net"
	"testing"
	"time"
)

func mk(t *testing.T, sc Scope) *Guard {
	t.Helper()
	if sc.Authorization == "" {
		sc.Authorization = "T-1"
	}
	g, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}
	g.SetLookup(func(h string) ([]net.IP, error) {
		switch h {
		case "lab.local":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		case "evil.example":
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}
		return nil, net.UnknownNetworkError("no")
	})
	return g
}

func TestDenyByDefault(t *testing.T) {
	g := mk(t, Scope{Targets: []string{"127.0.0.0/30"}, AllowActive: true})
	for _, tc := range []struct {
		target string
		want   bool
	}{{"127.0.0.1", true}, {"http://127.0.0.2:8081", true}, {"127.0.0.9", false}, {"8.8.8.8", false}, {"10.0.0.1", false}, {"", false}} {
		if got := g.Check(Action{Tool: "portscan", Target: tc.target, Kind: KindActive}).Allowed; got != tc.want {
			t.Errorf("%q allowed=%v want %v", tc.target, got, tc.want)
		}
	}
}

func TestExclusionBeatsTarget(t *testing.T) {
	g := mk(t, Scope{Targets: []string{"127.0.0.0/29"}, Exclusions: []string{"127.0.0.3"}, AllowActive: true})
	if g.Check(Action{Tool: "nmap", Target: "127.0.0.3", Kind: KindActive}).Allowed {
		t.Fatal("excluded host was allowed")
	}
	if !g.Check(Action{Tool: "nmap", Target: "127.0.0.4", Kind: KindActive}).Allowed {
		t.Fatal("non-excluded host denied")
	}
}

func TestActiveAndExploitGating(t *testing.T) {
	g := mk(t, Scope{Targets: []string{"127.0.0.1"}})
	if g.Check(Action{Tool: "nmap", Target: "127.0.0.1", Kind: KindActive}).Allowed {
		t.Error("active scan allowed although scope disallows it")
	}
	if !g.Check(Action{Tool: "webcheck", Target: "127.0.0.1", Kind: KindPassive}).Allowed {
		t.Error("passive denied")
	}
	if g.Check(Action{Tool: "metasploit", Target: "127.0.0.1", Kind: KindExploit}).Allowed {
		t.Error("exploit allowed although scope disallows it")
	}
	g2 := mk(t, Scope{Targets: []string{"127.0.0.1"}, AllowExploit: true})
	d := g2.Check(Action{Tool: "metasploit", Target: "127.0.0.1", Kind: KindExploit})
	if !d.Allowed || !d.NeedsApproval {
		t.Errorf("exploit decision = %+v, want allowed+needs approval", d)
	}
}

func TestLabOnlyEnforcedAtRegistration(t *testing.T) {
	if _, err := New(Scope{Targets: []string{"8.8.8.8"}, Authorization: "x"}); err == nil {
		t.Error("public IP accepted in lab-only mode")
	}
	if _, err := New(Scope{Targets: []string{"10.0.0.0/8"}, Authorization: "x"}); err == nil {
		t.Error("huge CIDR accepted")
	}
	if _, err := New(Scope{Targets: []string{"8.8.8.8"}, Authorization: "x", AllowNonLab: true}); err != nil {
		t.Errorf("organiser override rejected: %v", err)
	}
	if _, err := New(Scope{Targets: []string{"127.0.0.1"}}); err == nil {
		t.Error("scope without authorization reference accepted")
	}
	if _, err := New(Scope{Targets: []string{"*.example.com"}, Authorization: "x"}); err == nil {
		t.Error("wildcard accepted")
	}
}

func TestHostnameResolutionMustStayInScope(t *testing.T) {
	g := mk(t, Scope{Targets: []string{"lab.local", "evil.example"}, AllowActive: true, AllowNonLab: false})
	_ = g
	g = mk(t, Scope{Targets: []string{"lab.local"}, AllowActive: true})
	if !g.Check(Action{Tool: "nmap", Target: "lab.local", Kind: KindActive}).Allowed {
		t.Error("hostname resolving to loopback denied")
	}
	// A name that is listed but resolves to a public address must be refused (rebinding).
	g3, _ := New(Scope{Targets: []string{"evil.example"}, Authorization: "x", AllowActive: true})
	g3.SetLookup(func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil })
	if g3.Check(Action{Tool: "nmap", Target: "evil.example", Kind: KindActive}).Allowed {
		t.Error("hostname resolving to a public IP was allowed in lab-only mode")
	}
}

func TestPortAndToolAllowList(t *testing.T) {
	g := mk(t, Scope{Targets: []string{"127.0.0.1"}, Ports: []int{80, 8081}, AllowedTools: []string{"webcheck"}, AllowActive: true})
	if g.Check(Action{Tool: "webcheck", Target: "http://127.0.0.1:22", Kind: KindPassive}).Allowed {
		t.Error("port outside list allowed")
	}
	if !g.Check(Action{Tool: "webcheck", Target: "http://127.0.0.1:8081", Kind: KindPassive}).Allowed {
		t.Error("listed port denied")
	}
	if g.Check(Action{Tool: "nmap", Target: "127.0.0.1", Kind: KindActive}).Allowed {
		t.Error("tool outside list allowed")
	}
}

func TestExpiry(t *testing.T) {
	g := mk(t, Scope{Targets: []string{"127.0.0.1"}, Expires: time.Now().Add(-time.Hour)})
	if g.Check(Action{Tool: "webcheck", Target: "127.0.0.1", Kind: KindPassive}).Allowed {
		t.Error("expired authorization allowed")
	}
}

func TestToolAllowListDoesNotBlockMembershipChecks(t *testing.T) {
	g := mk(t, Scope{Targets: []string{"127.0.0.1"}, AllowedTools: []string{"webcheck"}})
	for _, tool := range []string{"request", "probe"} {
		if !g.Check(Action{Tool: tool, Target: "127.0.0.1", Kind: KindPassive}).Allowed {
			t.Errorf("%s membership check denied by the tool allow-list", tool)
		}
	}
	if g.Check(Action{Tool: "nmap", Target: "127.0.0.1", Kind: KindPassive}).Allowed {
		t.Error("tool allow-list no longer enforced for real tools")
	}
}
