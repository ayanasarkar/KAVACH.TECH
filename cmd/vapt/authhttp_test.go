package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// tc is a tiny browser: it keeps the session cookie and sends the per-run token the way the console does.
type tc struct {
	t      *testing.T
	s      *server
	cookie *http.Cookie
	remote string
}

func newTC(t *testing.T, s *server) *tc { return &tc{t: t, s: s, remote: "127.0.0.1:50000"} }

func (c *tc) do(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:8787"+path, rd)
	r.RemoteAddr = c.remote
	r.Header.Set("X-VAPT-Token", "tok")
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	w := httptest.NewRecorder()
	c.s.handler().ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == cookieName {
			if ck.MaxAge < 0 || ck.Value == "" {
				c.cookie = nil
			} else {
				c.cookie = &http.Cookie{Name: ck.Name, Value: ck.Value}
			}
		}
	}
	return w
}

func code(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status %d, want %d: %s", w.Code, want, w.Body.String())
	}
}

func TestAPIRequiresSignIn(t *testing.T) {
	s := newSrv(t)
	c := newTC(t, s)
	for _, p := range []string{"/api/config", "/api/lab-status", "/api/assessments", "/api/assessments/x", "/api/auth/users"} {
		w := c.do("GET", p, nil)
		code(t, w, 401)
		if strings.Contains(w.Body.String(), `"token"`) {
			t.Errorf("%s leaked the token to a signed-out caller", p)
		}
	}
	code(t, c.do("POST", "/api/assessments", map[string]any{"request": "scan 127.0.0.1"}), 401)
	w := c.do("GET", "/api/auth/status", nil) // status is public and says setup is needed
	code(t, w, 200)
	if !strings.Contains(w.Body.String(), `"setup_required":true`) {
		t.Errorf("status: %s", w.Body.String())
	}
}

func TestFirstRunSetupIsLocalAndOnce(t *testing.T) {
	s := newSrv(t)
	c := newTC(t, s)
	c.remote = "192.168.1.20:4000"
	code(t, c.do("POST", "/api/auth/setup", map[string]string{"name": "mallory", "password": testPW}), 403)
	if s.auth.HasUsers() {
		t.Fatal("a remote caller created the first account")
	}
	c.remote = "127.0.0.1:50000"
	code(t, c.do("POST", "/api/auth/setup", map[string]string{"name": "ayana", "password": "short"}), 422)
	w := c.do("POST", "/api/auth/setup", map[string]string{"name": "ayana", "display": "Ayana", "password": testPW})
	code(t, w, 200)
	var set *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == cookieName {
			set = ck
		}
	}
	if set == nil || !set.HttpOnly || set.SameSite != http.SameSiteStrictMode || set.Path != "/" {
		t.Fatalf("session cookie must be HttpOnly + SameSite=Strict: %+v", set)
	}
	code(t, c.do("GET", "/api/config", nil), 200)
	code(t, newTC(t, s).do("POST", "/api/auth/setup", map[string]string{"name": "second", "password": testPW}), 409)
}

func TestLoginLogoutAndNoSessionAfter(t *testing.T) {
	s := newSrv(t)
	s.auth.Setup("ayana", "", testPW)
	c := newTC(t, s)
	w := c.do("POST", "/api/auth/login", map[string]string{"name": "ayana", "password": "wrong wrong wrong"})
	code(t, w, 401)
	if c.cookie != nil || strings.Contains(w.Body.String(), "pbkdf2") {
		t.Error("a failed login must not start a session or reveal anything")
	}
	code(t, c.do("POST", "/api/auth/login", map[string]string{"name": "Ayana", "password": testPW}), 200)
	code(t, c.do("GET", "/api/config", nil), 200)
	old := c.cookie
	code(t, c.do("POST", "/api/auth/logout", nil), 200)
	c.cookie = old // replay the old cookie: the server must have ended the session
	code(t, c.do("GET", "/api/config", nil), 401)
}

func TestLockoutIsHTTP429(t *testing.T) {
	s := newSrv(t)
	s.auth.Setup("ayana", "", testPW)
	c := newTC(t, s)
	for i := 0; i < 5; i++ {
		c.do("POST", "/api/auth/login", map[string]string{"name": "ayana", "password": "bad bad bad bad"})
	}
	w := c.do("POST", "/api/auth/login", map[string]string{"name": "ayana", "password": testPW})
	code(t, w, 429)
	if w.Header().Get("Retry-After") == "" {
		t.Error("a lock-out must say when to retry")
	}
}

// The approver recorded in the audit chain is the signed-in account, whatever the request body claims.
func TestApprovalIdentityComesFromTheSession(t *testing.T) {
	s := newSrv(t)
	s.auth.Setup("ayana", "", testPW)
	c := newTC(t, s)
	code(t, c.do("POST", "/api/auth/login", map[string]string{"name": "ayana", "password": testPW}), 200)
	w := c.do("POST", "/api/assessments", map[string]any{"request": "scan 127.0.0.1", "authorization": "T-1", "targets": []string{"127.0.0.1"}, "hosts": []string{"127.0.0.1"}, "allow_active": true})
	code(t, w, 201)
	var id struct{ ID string }
	json.Unmarshal(w.Body.Bytes(), &id)
	code(t, c.do("POST", "/api/assessments/"+id.ID+"/start", nil), 202)
	deadline := time.Now().Add(8 * time.Second)
	for {
		var st struct {
			Assessment struct{ Phase string }
		}
		json.Unmarshal(c.do("GET", "/api/assessments/"+id.ID, nil).Body.Bytes(), &st)
		if st.Assessment.Phase == "awaiting_approval" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("plan never reached the approval gate (phase %q)", st.Assessment.Phase)
		}
		time.Sleep(50 * time.Millisecond)
	}
	code(t, c.do("POST", "/api/assessments/"+id.ID+"/deny", map[string]string{"analyst": "mallory", "reason": "test"}), 202)
	var au struct {
		Entries []struct{ Actor, Type string }
	}
	json.Unmarshal(c.do("GET", "/api/assessments/"+id.ID+"/audit", nil).Body.Bytes(), &au)
	var sawSession, sawDeny bool
	for _, e := range au.Entries {
		if strings.Contains(e.Actor, "mallory") {
			t.Errorf("a name typed in the request body reached the audit chain: %+v", e)
		}
		if e.Type == "analyst_session" && e.Actor == "ayana" {
			sawSession = true
		}
		if strings.HasPrefix(e.Actor, "analyst:ayana") {
			sawDeny = true
		}
	}
	if !sawSession || !sawDeny {
		t.Errorf("want the opening and the denial recorded under the account, got %+v", au.Entries)
	}
}

func TestViewerCanReadButNotAct(t *testing.T) {
	s := newSrv(t)
	adm, _, _ := s.auth.Login("x", "y", "z") // no users yet: must fail cleanly
	_ = adm
	s.auth.Setup("ayana", "", testPW)
	a := newTC(t, s)
	code(t, a.do("POST", "/api/auth/login", map[string]string{"name": "ayana", "password": testPW}), 200)
	code(t, a.do("POST", "/api/auth/users", map[string]string{"name": "vera", "password": "violet orchid lantern", "role": "viewer"}), 201)
	code(t, a.do("POST", "/api/auth/users", map[string]string{"name": "sam", "password": "granite meadow harbour", "role": "analyst"}), 201)

	v := newTC(t, s)
	code(t, v.do("POST", "/api/auth/login", map[string]string{"name": "vera", "password": "violet orchid lantern"}), 200)
	code(t, v.do("GET", "/api/config", nil), 200)
	code(t, v.do("GET", "/api/assessments", nil), 200)
	code(t, v.do("POST", "/api/assessments", map[string]any{"request": "scan 127.0.0.1"}), 403)
	code(t, v.do("POST", "/api/guard-check", map[string]any{"targets": []string{"127.0.0.1"}, "check": []string{"8.8.8.8"}}), 200)
	code(t, v.do("GET", "/api/auth/users", nil), 403)
	code(t, v.do("POST", "/api/auth/users", map[string]string{"name": "eve", "password": "cobalt river anchor", "role": "admin"}), 403)
	code(t, v.do("GET", "/api/auth/audit", nil), 403)

	n := newTC(t, s)
	code(t, n.do("POST", "/api/auth/login", map[string]string{"name": "sam", "password": "granite meadow harbour"}), 200)
	code(t, n.do("GET", "/api/auth/users", nil), 403) // analysts run assessments, they do not manage accounts
	code(t, n.do("POST", "/api/assessments", map[string]any{"request": "scan 127.0.0.1", "authorization": "T-1", "targets": []string{"127.0.0.1"}, "hosts": []string{"127.0.0.1"}}), 201)

	w := a.do("GET", "/api/auth/audit", nil)
	code(t, w, 200)
	if !strings.Contains(w.Body.String(), `"status":"verified"`) || !strings.Contains(w.Body.String(), "login_failed") {
		t.Errorf("admin audit view: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), testPW) {
		t.Error("the account audit must not contain passwords")
	}
	code(t, a.do("POST", "/api/auth/users/vera/disable", nil), 200)
	code(t, v.do("GET", "/api/config", nil), 401) // disabling ends their session at once
}

func TestChangePasswordOverHTTP(t *testing.T) {
	s := newSrv(t)
	s.auth.Setup("ayana", "", testPW)
	c := newTC(t, s)
	code(t, c.do("POST", "/api/auth/login", map[string]string{"name": "ayana", "password": testPW}), 200)
	code(t, c.do("POST", "/api/auth/password", map[string]string{"old": "nope nope nope", "new": "another long secret"}), 422)
	code(t, c.do("POST", "/api/auth/password", map[string]string{"old": testPW, "new": "another long secret"}), 200)
	code(t, c.do("GET", "/api/config", nil), 200)
	code(t, newTC(t, s).do("POST", "/api/auth/login", map[string]string{"name": "ayana", "password": testPW}), 401)
}

func TestSecurityHeaders(t *testing.T) {
	s := newSrv(t)
	r := httptest.NewRequest("GET", "http://127.0.0.1:8787/console", nil)
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("pages must refuse framing (the approval buttons are clickjacking targets): %v", w.Header())
	}
	w2 := newTC(t, s).do("GET", "/api/auth/status", nil)
	if w2.Header().Get("Cache-Control") != "no-store" {
		t.Error("API responses must not be cached")
	}
}
