package adapters

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestInferScheme(t *testing.T) {
	for _, tc := range []struct {
		in       string
		want     string
		inferred bool
	}{
		{"www.example.com:443", "https://www.example.com:443", true},
		{"www.example.com:8443", "https://www.example.com:8443", true},
		{"www.example.com:80", "http://www.example.com:80", true},
		{"www.example.com:8000", "http://www.example.com:8000", true},
		{"www.example.com", "http://www.example.com", true},
		{"[::1]:443", "https://[::1]:443", true},
		// an explicit scheme is always respected, even on a TLS port
		{"http://www.example.com:443", "http://www.example.com:443", false},
		{"https://www.example.com", "https://www.example.com", false},
	} {
		got, inferred := inferScheme(tc.in)
		if got != tc.want || inferred != tc.inferred {
			t.Errorf("inferScheme(%q) = %q,%v want %q,%v", tc.in, got, inferred, tc.want, tc.inferred)
		}
	}
}

// A scheme-less target whose guessed scheme is wrong must be corrected once, and the correction must be
// written into the raw evidence so it is auditable.
func TestWebCheckFallsBackFromHTTPToHTTPSOnTLSPort(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "<html><title>tls</title></html>")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	// The port is random, so the guess is plain http and the TLS server answers 400.
	res, err := (&WebCheck{}).Run(context.Background(), Job{Target: u.Host})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "https://"+u.Host) || !strings.Contains(res.Summary, "fallback") {
		t.Errorf("summary does not show the corrected scheme: %q", res.Summary)
	}
	if !strings.Contains(res.Raw, "NOTE protocol fallback") {
		t.Errorf("fallback not recorded in raw evidence:\n%s", res.Raw)
	}
	if len(res.Services) != 1 || res.Services[0].Name != "https" {
		t.Errorf("service must be labelled https: %+v", res.Services)
	}
	hsts := false
	for _, f := range res.Findings {
		if f.Key == "web:missing-header:hsts" {
			hsts = true
			if f.Excerpt == "" || strings.Contains(f.Excerpt, "-> 400") {
				t.Errorf("HSTS finding was built from the 400 response: %q", f.Excerpt)
			}
		}
	}
	if !hsts {
		t.Errorf("HSTS finding missing after fallback: %+v", res.Findings)
	}
}

func TestWebCheckFallsBackFromHTTPSToHTTPOnPlainPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "<html><title>plain</title></html>")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	tlsPorts[port] = true // pretend this port is a conventional TLS port, so the guess is https
	defer delete(tlsPorts, port)
	res, err := (&WebCheck{}).Run(context.Background(), Job{Target: u.Host})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Raw, "NOTE protocol fallback") || len(res.Services) != 1 || res.Services[0].Name != "http" {
		t.Errorf("expected recorded fallback to http, services=%+v\n%s", res.Services, res.Raw)
	}
}

// An explicit scheme from the caller is never second-guessed.
func TestWebCheckExplicitSchemeIsNotRetried(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	res, err := (&WebCheck{}).Run(context.Background(), Job{Target: "http://" + u.Host})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Raw, "protocol fallback") {
		t.Errorf("explicit http:// must not be silently switched:\n%s", res.Raw)
	}
}
