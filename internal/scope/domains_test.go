package scope

import (
	"net"
	"testing"
)

// Authorized domains let a public hostname registered as a target bypass the
// lab-only (private/loopback) requirement — but only within that domain's own
// tree, and only once the resolved address is itself a genuine public one.

func TestAuthorizedDomainAllowsPublicTargetWithoutAllowNonLab(t *testing.T) {
	g, err := New(Scope{Authorization: "t", Targets: []string{"www.hackthecore.in"}, AuthorizedDomains: []string{"hackthecore.in"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g.SetLookup(func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil })
	if d := g.Check(Action{Tool: "webcheck", Target: "www.hackthecore.in", Kind: KindPassive}); !d.Allowed {
		t.Errorf("authorized-domain target was denied: %s", d.Reason)
	}
}

func TestAuthorizedDomainRejectsUnrelatedPublicTarget(t *testing.T) {
	g, err := New(Scope{Authorization: "t", Targets: []string{"example.com"}, AuthorizedDomains: []string{"hackthecore.in"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g.SetLookup(func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.5")}, nil })
	if d := g.Check(Action{Tool: "webcheck", Target: "example.com", Kind: KindPassive}); d.Allowed {
		t.Errorf("BYPASS: a public target outside every authorized domain was allowed (%s)", d.Reason)
	}
}

func TestAuthorizedDomainDoesNotCoverUnrelatedSuffix(t *testing.T) {
	// evil-hackthecore.in shares no label boundary with hackthecore.in.
	g, err := New(Scope{Authorization: "t", Targets: []string{"evil-hackthecore.in"}, AuthorizedDomains: []string{"hackthecore.in"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g.SetLookup(func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.6")}, nil })
	if d := g.Check(Action{Tool: "webcheck", Target: "evil-hackthecore.in", Kind: KindPassive}); d.Allowed {
		t.Errorf("BYPASS: evil-hackthecore.in was allowed under an authorization for hackthecore.in (%s)", d.Reason)
	}
}

func TestAuthorizedDomainStillHonoursExclusions(t *testing.T) {
	g, err := New(Scope{Authorization: "t", Targets: []string{"hackthecore.in"}, AuthorizedDomains: []string{"hackthecore.in"}, Exclusions: []string{"admin.hackthecore.in"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g.SetLookup(func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil })
	if d := g.Check(Action{Tool: "webcheck", Target: "admin.hackthecore.in", Kind: KindPassive}); d.Allowed {
		t.Errorf("BYPASS: excluded host admin.hackthecore.in was allowed via the authorized domain (%s)", d.Reason)
	}
}

func TestAuthorizedDomainRejectsPrivateResolution(t *testing.T) {
	g, err := New(Scope{Authorization: "t", Targets: []string{"hackthecore.in"}, AuthorizedDomains: []string{"hackthecore.in"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Simulated DNS rebinding: a public-looking domain resolves to a private address.
	g.SetLookup(func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.5")}, nil })
	if d := g.Check(Action{Tool: "webcheck", Target: "hackthecore.in", Kind: KindPassive}); d.Allowed {
		t.Errorf("REBINDING: authorized-domain target resolving to private address 10.0.0.5 was allowed (%s)", d.Reason)
	}
}

func TestCheckDialAuthorizedDomainRejectsPrivateRebind(t *testing.T) {
	g, err := New(Scope{Authorization: "t", Targets: []string{"hackthecore.in"}, AuthorizedDomains: []string{"hackthecore.in"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := g.CheckDial("hackthecore.in", net.ParseIP("127.0.0.1")); err == nil {
		t.Errorf("REBINDING at connect time: hackthecore.in dialing 127.0.0.1 was allowed")
	}
	if err := g.CheckDial("hackthecore.in", net.ParseIP("203.0.113.10")); err != nil {
		t.Errorf("a genuine public resolution was refused: %v", err)
	}
}

func TestAuthorizedDomainDoesNotExemptIPLiteralTargets(t *testing.T) {
	// An authorized domain string never exempts a bare IP literal: domains and
	// addresses are different trust boundaries.
	_, err := New(Scope{Authorization: "t", Targets: []string{"203.0.113.10"}, AuthorizedDomains: []string{"hackthecore.in"}})
	if err == nil {
		t.Fatalf("a public IP literal was accepted as in-scope even though it matches no authorized domain")
	}
}

func TestAuthorizedDomainRejectsMalformedEntry(t *testing.T) {
	for _, bad := range []string{"https://hackthecore.in", "*.hackthecore.in", "203.0.113.10", "localhost"} {
		if _, err := New(Scope{Authorization: "t", Targets: []string{"127.0.0.1"}, AuthorizedDomains: []string{bad}}); err == nil {
			t.Errorf("authorized_domains entry %q should have been rejected as malformed", bad)
		}
	}
}
