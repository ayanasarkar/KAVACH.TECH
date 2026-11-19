package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ayanasarkar/vapt-agent/internal/auth"
)

func TestParseHosts(t *testing.T) {
	got := parseHosts(" Kavach.onrender.com , https://demo.example.org:443/path ,*, ", "", "other.test:8080")
	for _, want := range []string{"kavach.onrender.com", "demo.example.org", "other.test"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if len(got) != 3 || got["*"] || got[""] {
		t.Errorf("a wildcard or empty entry must never become an allowed host: %v", got)
	}
}

// A hosted deployment is addressed by its public name. That name must pass the Host check, and only that name.
func TestConfiguredHostPassesAndOthersStillFail(t *testing.T) {
	s := newSrv(t)
	ck := signedIn(t, s)
	get := func(host string) int {
		r := httptest.NewRequest("GET", "http://"+host+"/api/config", nil)
		r.Host = host
		r.AddCookie(ck)
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		return w.Code
	}
	if c := get("kavach.onrender.com"); c != 403 {
		t.Fatalf("with no host configured a public name must be refused (DNS-rebinding guard), got %d", c)
	}
	s.allowedHosts = parseHosts("Kavach.onrender.com")
	for _, h := range []string{"kavach.onrender.com", "KAVACH.onrender.com:443"} {
		if c := get(h); c != 200 {
			t.Errorf("configured host %q should work, got %d", h, c)
		}
	}
	for _, h := range []string{"evil.example", "kavach.onrender.com.evil.example", "xkavach.onrender.com", "0.0.0.0"} {
		if c := get(h); c != 403 {
			t.Errorf("host %q must still be refused, got %d", h, c)
		}
	}
}

func TestConfiguredHostStillRejectsCrossOrigin(t *testing.T) {
	s := newSrv(t)
	s.allowedHosts = parseHosts("kavach.onrender.com")
	r := httptest.NewRequest("GET", "https://kavach.onrender.com/api/config", nil)
	r.Host = "kavach.onrender.com"
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("a cross-origin request to the hosted name must be refused, got %d", w.Code)
	}
}

func TestHealthzNeedsNeitherHostNorLogin(t *testing.T) {
	s := newSrv(t)
	for _, m := range []string{"GET", "HEAD"} {
		r := httptest.NewRequest(m, "http://10.1.2.3:10000/healthz", nil)
		r.Host = "10.1.2.3:10000"
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Errorf("%s /healthz = %d", m, w.Code)
		}
		if m == "GET" && strings.TrimSpace(w.Body.String()) != "ok" {
			t.Errorf("body %q", w.Body.String())
		}
	}
	r := httptest.NewRequest("POST", "http://10.1.2.3:10000/healthz", nil)
	r.Host = "10.1.2.3:10000"
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("only GET and HEAD are exempt from the host check, POST got %d", w.Code)
	}
	r = httptest.NewRequest("GET", "http://10.1.2.3:10000/api/config", nil)
	r.Host = "10.1.2.3:10000"
	w = httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("the exemption must not leak to other paths, got %d", w.Code)
	}
}

func TestSessionCookieIsSecureBehindATLSProxy(t *testing.T) {
	s := newSrv(t)
	s.allowedHosts = parseHosts("kavach.onrender.com")
	if _, err := s.auth.Setup("ayana", "", testPW); err != nil {
		t.Fatal(err)
	}
	login := func(proto string) *http.Cookie {
		r := httptest.NewRequest("POST", "http://kavach.onrender.com/api/auth/login", strings.NewReader(`{"name":"ayana","password":"`+testPW+`"}`))
		r.Host = "kavach.onrender.com"
		r.RemoteAddr = "10.0.0.7:41000" // the proxy, not loopback
		if proto != "" {
			r.Header.Set("X-Forwarded-Proto", proto)
		}
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("login via proxy (%q) = %d %s", proto, w.Code, w.Body.String())
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == cookieName {
				return c
			}
		}
		t.Fatal("no session cookie")
		return nil
	}
	if c := login("https"); !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("behind an HTTPS proxy the cookie must be Secure+HttpOnly+SameSite=Strict: %+v", c)
	}
	if c := login(""); c.Secure {
		t.Errorf("plain HTTP (local run) must not set Secure or the console would lose its session: %+v", c)
	}
}

func TestFirstAdminCannotBeCreatedThroughAProxy(t *testing.T) {
	s := newSrv(t)
	s.allowedHosts = parseHosts("kavach.onrender.com")
	r := httptest.NewRequest("POST", "http://kavach.onrender.com/api/auth/setup", strings.NewReader(`{"name":"intruder","password":"`+testPW+`"}`))
	r.Host = "kavach.onrender.com"
	r.RemoteAddr = "10.0.0.7:41000"
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Code == 200 || w.Code == 201 || s.auth.HasUsers() {
		t.Fatalf("a remote caller must not be able to claim the first administrator account: %d %s", w.Code, w.Body.String())
	}
}

func labCreate(t *testing.T, s *server, body string) int {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/assessments", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, auth.Principal{Name: "tester", Role: auth.Analyst}))
	r.Header.Set("X-VAPT-Token", "tok")
	w := httptest.NewRecorder()
	s.create(w, r)
	var o map[string]string
	json.NewDecoder(w.Body).Decode(&o)
	if w.Code == 201 {
		t.Cleanup(func() {
			s.mu.Lock()
			a := s.items[o["id"]]
			s.mu.Unlock()
			if a != nil {
				a.Close()
			}
		})
	}
	return w.Code
}

func TestLabOnlyModeRefusesWiderScope(t *testing.T) {
	const lab = `"request":"scan 127.0.0.1","authorization":"T-1","targets":["127.0.0.1"],"hosts":["127.0.0.1"]`
	s := newSrv(t)
	s.labOnly = true
	if c := labCreate(t, s, `{`+lab+`}`); c != 201 {
		t.Fatalf("a plain lab scope must still work in lab-only mode, got %d", c)
	}
	if c := labCreate(t, s, `{`+lab+`,"allow_non_lab":true}`); c != 403 {
		t.Errorf("allow_non_lab must be refused in lab-only mode, got %d", c)
	}
	if c := labCreate(t, s, `{`+lab+`,"authorized_domains":["example.com"]}`); c != 403 {
		t.Errorf("authorized_domains must be refused in lab-only mode, got %d", c)
	}
	// the dry-run endpoint must not offer a verdict the real endpoint would refuse
	r := httptest.NewRequest("POST", "/api/guard-check", strings.NewReader(`{`+lab+`,"allow_non_lab":true,"check":["8.8.8.8"]}`))
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, auth.Principal{Name: "tester", Role: auth.Analyst}))
	w := httptest.NewRecorder()
	s.guardCheck(w, r)
	if w.Code != 403 {
		t.Errorf("guard-check with allow_non_lab in lab-only mode = %d", w.Code)
	}
}

func TestWithoutLabOnlyTheLocalBehaviourIsUnchanged(t *testing.T) {
	s := newSrv(t)
	if c := labCreate(t, s, `{"request":"scan 127.0.0.1","authorization":"T-1","targets":["127.0.0.1"],"hosts":["127.0.0.1"],"allow_non_lab":true}`); c != 201 {
		t.Fatalf("local runs keep the organiser override, got %d", c)
	}
}
