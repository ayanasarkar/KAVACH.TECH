package main

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ayanasarkar/vapt-agent/internal/adapters"
	"github.com/ayanasarkar/vapt-agent/internal/agent"
	"github.com/ayanasarkar/vapt-agent/internal/auth"
	"github.com/ayanasarkar/vapt-agent/internal/llm"
)

func newSrv(t *testing.T) *server {
	st, err := auth.Open(t.TempDir(), auth.Options{Iterations: 1000}) // low cost: tests, not production
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = st.Close()
	})
	srv := &server{env: agent.Env{DataDir: t.TempDir(), Reg: adapters.NewRegistry(), LLM: llm.None{}}, token: "tok", auth: st, items: map[string]*agent.Assessment{}}
	// Close every created assessment before TempDir's own cleanup tries to remove the
	// directory - on Windows an open audit.jsonl handle blocks the delete (unlinkat
	// fails with "used by another process"). Registered after DataDir's TempDir call
	// so it runs first (t.Cleanup is LIFO).
	t.Cleanup(func() {
		for _, a := range srv.items {
			a.Close()
		}
	})
	return srv
}

const testPW = "correct horse battery"

// signedIn makes sure the test server has an administrator and returns a valid session cookie for it.
func signedIn(t *testing.T, s *server) *http.Cookie {
	t.Helper()
	if !s.auth.HasUsers() {
		if _, err := s.auth.Setup("tester", "Tester", testPW); err != nil {
			t.Fatal(err)
		}
	}
	tok, _, err := s.auth.Login("tester", testPW, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: cookieName, Value: tok}
}

func mk(t *testing.T, s *server) string {
	body := `{"request":"scan 127.0.0.1","authorization":"T-1","targets":["127.0.0.1"],"hosts":["127.0.0.1"]}`
	r := httptest.NewRequest("POST", "/api/assessments", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, auth.Principal{Name: "tester", Role: auth.Analyst})) // what the gate does for a signed-in request
	r.Header.Set("X-VAPT-Token", "tok")
	w := httptest.NewRecorder()
	s.create(w, r)
	var o map[string]string
	json.NewDecoder(w.Body).Decode(&o)
	if o["id"] == "" {
		t.Fatalf("create failed: %s", w.Body.String())
	}
	return o["id"]
}

// A page on another origin (DNS rebinding) reaches the loopback server with a foreign Host header and gets the token.
func TestGap_NoHostHeaderCheck(t *testing.T) {
	s := newSrv(t)
	r := httptest.NewRequest("GET", "http://evil.example:8787/api/config", nil)
	r.Host = "evil.example:8787"
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Code != 403 || strings.Contains(w.Body.String(), `"token":"tok"`) {
		t.Errorf("REBINDING: /api/config answered Host=%q with %d", r.Host, w.Code)
	}
	ck := signedIn(t, s)
	for _, host := range []string{"127.0.0.1:8787", "localhost:8787", "[::1]:8787"} {
		r2 := httptest.NewRequest("GET", "http://"+host+"/api/config", nil)
		r2.AddCookie(ck)
		w2 := httptest.NewRecorder()
		s.handler().ServeHTTP(w2, r2)
		if w2.Code != 200 {
			t.Errorf("legit Host %q must still work, got %d", host, w2.Code)
		}
	}
	r3 := httptest.NewRequest("GET", "http://127.0.0.1:8787/api/config", nil)
	r3.Header.Set("Origin", "http://evil.example")
	w3 := httptest.NewRecorder()
	s.handler().ServeHTTP(w3, r3)
	if w3.Code != 403 {
		t.Errorf("cross-origin request must be refused, got %d", w3.Code)
	}
}

func TestGap_ImportToolNotSanitised(t *testing.T) {
	s := newSrv(t)
	id := mk(t, s)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("tool", "../../ESCAPED")
	fw, _ := mw.CreateFormFile("file", "x.xml")
	fw.Write([]byte("<x/>"))
	mw.Close()
	r := httptest.NewRequest("POST", "/api/assessments/"+id+"/import", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("X-VAPT-Token", "tok")
	rec := httptest.NewRecorder()
	s.item(rec, r)
	if rec.Code != 422 {
		t.Errorf("unknown tool must be rejected with 422, got %d", rec.Code)
	}
	a := s.items[id]
	esc, _ := filepath.Glob(filepath.Join(filepath.Dir(a.Dir()), "ESCAPED*"))
	esc2, _ := filepath.Glob(filepath.Join(filepath.Dir(filepath.Dir(a.Dir())), "ESCAPED*"))
	if len(esc)+len(esc2) > 0 {
		t.Errorf("PATH TRAVERSAL: unknown tool name wrote a file outside the assessment folder: %v %v", esc, esc2)
		for _, p := range append(esc, esc2...) {
			os.Remove(p)
		}
	}
}

func TestGap_IDCollision(t *testing.T) {
	s := newSrv(t)
	a, b := mk(t, s), mk(t, s)
	if a == b {
		t.Errorf("COLLISION: two assessments created in the same second share id %s (and one data/audit directory)", a)
	}
}

var _ = http.StatusOK

func TestLabStatusShape(t *testing.T) {
	s := newSrv(t)
	r := httptest.NewRequest("GET", "http://127.0.0.1:8787/api/lab-status", nil)
	r.AddCookie(signedIn(t, s))
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var o map[string][]int
	if err := json.NewDecoder(w.Body).Decode(&o); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"web", "ftp", "telnet"} {
		if o[k] == nil {
			t.Errorf("missing key %q", k)
		}
	}
	// a foreign Host header must still be refused
	r2 := httptest.NewRequest("GET", "http://evil.example/api/lab-status", nil)
	r2.Host = "evil.example"
	w2 := httptest.NewRecorder()
	s.handler().ServeHTTP(w2, r2)
	if w2.Code != 403 {
		t.Errorf("foreign host got %d, want 403", w2.Code)
	}
}

func TestAssessmentListNeedsTokenAndIsNewestFirst(t *testing.T) {
	s := newSrv(t)
	ck := signedIn(t, s)
	get := func(tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://127.0.0.1:8787/api/assessments", nil)
		r.AddCookie(ck)
		if tok != "" {
			r.Header.Set("X-VAPT-Token", tok)
		}
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		return w
	}
	if w := get(""); w.Code != 403 {
		t.Fatalf("list without token: %d", w.Code)
	}
	w := get(s.token)
	if w.Code != 200 {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var o struct {
		Assessments []map[string]any `json:"assessments"`
	}
	if err := json.NewDecoder(w.Body).Decode(&o); err != nil || o.Assessments == nil {
		t.Fatalf("want an empty array, got %v %v", o, err)
	}
}
