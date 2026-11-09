package scope

import (
	"errors"
	"net"
	"testing"
	"time"
)

// Exclusions given as hostnames must also exclude the same machine reached by IP or by a trailing-dot name.
func TestGap_HostnameExclusionBypass(t *testing.T) {
	g, err := New(Scope{Authorization: "t", Targets: []string{"127.0.0.0/24"}, Exclusions: []string{"admin.lab"}})
	if err != nil {
		t.Fatal(err)
	}
	g.SetLookup(func(h string) ([]net.IP, error) {
		if h == "admin.lab" || h == "admin.lab." {
			return []net.IP{net.ParseIP("127.0.0.9")}, nil
		}
		return nil, errors.New("nxdomain")
	})
	for _, tgt := range []string{"127.0.0.9", "admin.lab."} {
		if d := g.Check(Action{Tool: "probe", Target: tgt, Kind: KindPassive}); d.Allowed {
			t.Errorf("BYPASS: %q reaches the excluded host admin.lab but was ALLOWED (%s)", tgt, d.Reason)
		}
	}
}

// In lab-only mode, a hostname whose resolution cannot be verified must not pass the lab-only check.
func TestGap_UnresolvableHostnameFailsOpen(t *testing.T) {
	g, _ := New(Scope{Authorization: "t", Targets: []string{"app.lab"}})
	g.SetLookup(func(string) ([]net.IP, error) { return nil, errors.New("nxdomain") })
	if d := g.Check(Action{Tool: "probe", Target: "app.lab", Kind: KindPassive}); d.Allowed {
		t.Errorf("FAIL-OPEN: unresolvable hostname allowed in lab-only mode (%s)", d.Reason)
	}
}

// A slow DNS lookup must not freeze every other guard check.
func TestGap_LookupHoldsGuardMutex(t *testing.T) {
	g, _ := New(Scope{Authorization: "t", Targets: []string{"127.0.0.0/24"}})
	g.SetLookup(func(h string) ([]net.IP, error) {
		if h == "slow.lab" {
			time.Sleep(600 * time.Millisecond)
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	})
	go g.Check(Action{Tool: "probe", Target: "slow.lab", Kind: KindPassive})
	time.Sleep(80 * time.Millisecond)
	start := time.Now()
	g.Check(Action{Tool: "probe", Target: "127.0.0.1", Kind: KindPassive})
	if el := time.Since(start); el > 250*time.Millisecond {
		t.Errorf("STALL: an IP-literal check waited %v behind another host's DNS lookup (mutex held during lookup)", el.Round(time.Millisecond))
	}
}
