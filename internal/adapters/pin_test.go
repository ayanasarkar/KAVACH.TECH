package adapters

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// guardFor builds the real scope guard for an authorised public domain, so these tests exercise KAVACH's actual
// connect-time policy and not a stand-in.
func guardFor(t *testing.T, domain string) *scope.Guard {
	t.Helper()
	g, err := scope.New(scope.Scope{Name: "t", Authorization: "T-1", Targets: []string{domain}, AuthorizedDomains: []string{domain}, AllowActive: true})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func fakeDNS(t *testing.T, answers ...string) {
	t.Helper()
	old := lookupIP
	t.Cleanup(func() { lookupIP = old })
	lookupIP = func(string) ([]net.IP, error) {
		var out []net.IP
		for _, a := range answers {
			out = append(out, net.ParseIP(a))
		}
		return out, nil
	}
}

// The rebinding attack: the name looked public to the plan-time check, but when the tool is about to run it resolves
// to the cloud metadata address. nmap must not be launched at all.
func TestNmapRefusesNameReboundToMetadata(t *testing.T) {
	args := stubNmap(t)
	fakeDNS(t, "169.254.169.254")
	g := guardFor(t, "lab.example.test")
	_, err := (&Nmap{}).Run(context.Background(), Job{Host: "lab.example.test", Options: map[string]string{}, DialCheck: g.CheckDial})
	if err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Fatalf("expected a DNS-rebinding refusal, got %v", err)
	}
	if _, statErr := os.Stat(args); statErr == nil {
		t.Error("nmap was launched even though the name resolved to 169.254.169.254")
	}
}

// One bad answer among good ones is enough to refuse (round-robin / split-horizon tricks).
func TestNmapRefusesIfAnyAnswerIsOutOfScope(t *testing.T) {
	args := stubNmap(t)
	fakeDNS(t, "93.184.216.34", "127.0.0.1")
	g := guardFor(t, "lab.example.test")
	if _, err := (&Nmap{}).Run(context.Background(), Job{Host: "lab.example.test", Options: map[string]string{}, DialCheck: g.CheckDial}); err == nil {
		t.Fatal("a name with one loopback answer must be refused")
	}
	if _, statErr := os.Stat(args); statErr == nil {
		t.Error("nmap was launched")
	}
}

// The happy path: nmap is handed the address that passed the check, never the name it could re-resolve.
func TestNmapIsPinnedToTheCheckedAddress(t *testing.T) {
	args := stubNmap(t)
	fakeDNS(t, "93.184.216.34")
	g := guardFor(t, "lab.example.test")
	if _, err := (&Nmap{}).Run(context.Background(), Job{Host: "lab.example.test", Options: map[string]string{}, DialCheck: g.CheckDial}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(args)
	got := strings.Fields(string(b))
	if last := got[len(got)-1]; last != "93.184.216.34" {
		t.Errorf("nmap target = %q, want the checked address 93.184.216.34 (full args: %s)", last, strings.TrimSpace(string(b)))
	}
	if strings.Contains(string(b), "lab.example.test") {
		t.Error("the hostname still reached nmap, so it could resolve it again")
	}
}

// Lab runs are unchanged: an IP literal is checked and passed through as is.
func TestNmapIPLiteralUnchanged(t *testing.T) {
	args := stubNmap(t)
	g, err := scope.New(scope.Scope{Name: "lab", Authorization: "L-1", Targets: []string{"127.0.0.0/30"}, AllowActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Nmap{}).Run(context.Background(), Job{Host: "127.0.0.1", Options: map[string]string{}, DialCheck: g.CheckDial}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(args)
	got := strings.Fields(string(b))
	if got[len(got)-1] != "127.0.0.1" {
		t.Errorf("lab target changed: %s", strings.TrimSpace(string(b)))
	}
}

// Fail closed: if the name cannot be resolved for the check, nothing runs.
func TestNmapFailsClosedWhenNameDoesNotResolve(t *testing.T) {
	args := stubNmap(t)
	old := lookupIP
	t.Cleanup(func() { lookupIP = old })
	lookupIP = func(string) ([]net.IP, error) { return nil, &net.DNSError{Err: "no such host", Name: "x"} }
	g := guardFor(t, "lab.example.test")
	if _, err := (&Nmap{}).Run(context.Background(), Job{Host: "lab.example.test", Options: map[string]string{}, DialCheck: g.CheckDial}); err == nil {
		t.Fatal("expected an error")
	}
	if _, statErr := os.Stat(args); statErr == nil {
		t.Error("nmap was launched without a successful scope check")
	}
}
