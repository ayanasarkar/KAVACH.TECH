package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/ayanasarkar/vapt-agent/internal/audit"
	"github.com/ayanasarkar/vapt-agent/internal/auth"
)

// KAVACH's own sign-in. A session is an opaque random token in an HttpOnly, SameSite=Strict cookie; the server keeps
// the session, the browser keeps nothing it could leak to a script. Signing in says who the analyst is and which role
// they hold. It grants no targets: scope still comes only from the scope form and the scope guard.

const cookieName = "kavach_session"

type ctxKey struct{}

// Routes that work without a session. Everything else under /api/ needs one.
var publicAPI = map[string]bool{"/api/auth/status": true, "/api/auth/login": true, "/api/auth/setup": true}

func principalOf(r *http.Request) (auth.Principal, bool) {
	p, ok := r.Context().Value(ctxKey{}).(auth.Principal)
	return p, ok
}

// actor is the signed-in account name that every approval, denial and request is recorded under. It is never taken from
// the request body, so a client cannot approve as someone else.
func actor(w http.ResponseWriter, r *http.Request) (string, bool) {
	if p, ok := principalOf(r); ok {
		return p.Name, true
	}
	fail(w, 401, "sign in required")
	return "", false
}

// mayWrite: viewers may read, ask the grounded chat questions and dry-run the scope guard. Analysts and admins may do the rest.
func mayWrite(role auth.Role, path string) bool {
	if role == auth.Admin || role == auth.Analyst {
		return true
	}
	return strings.HasSuffix(path, "/chat") || path == "/api/guard-check" || strings.HasPrefix(path, "/api/auth/")
}

// gate refuses any /api/ request that has no valid session (other than sign-in itself) and enforces roles on writes.
func (s *server) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || publicAPI[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		p, _, ok := s.session(r)
		if !ok {
			jsonOut(w, 401, map[string]any{"error": "sign in required", "auth": "required", "setup_required": !s.auth.HasUsers()})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !mayWrite(p.Role, r.URL.Path) {
			fail(w, 403, "your role ("+string(p.Role)+") can read and ask questions but cannot run, approve or change anything")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

func (s *server) session(r *http.Request) (auth.Principal, string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return auth.Principal{}, "", false
	}
	p, ok := s.auth.Lookup(c.Value)
	return p, c.Value, ok
}

func setSession(w http.ResponseWriter, r *http.Request, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: maxAge})
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func isLoopback(r *http.Request) bool {
	ip := net.ParseIP(clientIP(r))
	return ip != nil && ip.IsLoopback()
}

type authState struct {
	SetupRequired bool            `json:"setup_required"`
	User          *auth.Principal `json:"user"`
	MinPassword   int             `json:"min_password"`
}

func (s *server) authError(w http.ResponseWriter, err error) {
	var pe auth.PolicyError
	var le *auth.LockedError
	switch {
	case errors.Is(err, auth.ErrBadLogin):
		fail(w, 401, "Incorrect username or password.")
	case errors.As(err, &le):
		w.Header().Set("Retry-After", strconv.Itoa(int(le.Wait.Seconds())+1))
		fail(w, 429, le.Error())
	case errors.As(err, &pe):
		fail(w, 422, pe.Error())
	case errors.Is(err, auth.ErrForbidden):
		fail(w, 403, err.Error())
	case errors.Is(err, auth.ErrNoUser):
		fail(w, 404, err.Error())
	case errors.Is(err, auth.ErrSetupDone):
		fail(w, 409, err.Error())
	default:
		fail(w, 500, "could not complete that: "+err.Error())
	}
}

func (s *server) authAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/"), "/")
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	post := r.Method == http.MethodPost
	switch {
	case path == "status" && r.Method == http.MethodGet:
		st := authState{SetupRequired: !s.auth.HasUsers(), MinPassword: 10}
		if p, _, ok := s.session(r); ok {
			st.User = &p
		}
		jsonOut(w, 200, st)

	case path == "setup" && post:
		if !isLoopback(r) { // the first administrator can only be created from the machine itself
			fail(w, 403, "first-run setup is only allowed from this machine")
			return
		}
		var in struct{ Name, Display, Password string }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			fail(w, 400, "bad JSON")
			return
		}
		if _, err := s.auth.Setup(in.Name, in.Display, in.Password); err != nil {
			s.authError(w, err)
			return
		}
		s.startSession(w, r, in.Name, in.Password)

	case path == "login" && post:
		var in struct{ Name, Password string }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			fail(w, 400, "bad JSON")
			return
		}
		s.startSession(w, r, in.Name, in.Password)

	case path == "logout" && post:
		if c, err := r.Cookie(cookieName); err == nil {
			s.auth.Logout(c.Value)
		}
		setSession(w, r, "", -1)
		jsonOut(w, 200, authState{SetupRequired: !s.auth.HasUsers(), MinPassword: 10})

	case path == "password" && post:
		p, tok, ok := s.session(r)
		if !ok {
			fail(w, 401, "sign in required")
			return
		}
		var in struct{ Old, New string }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			fail(w, 400, "bad JSON")
			return
		}
		if err := s.auth.ChangePassword(p.Name, tok, in.Old, in.New); err != nil {
			s.authError(w, err)
			return
		}
		jsonOut(w, 200, map[string]string{"status": "password changed; your other sessions were signed out"})

	case path == "users" && r.Method == http.MethodGet:
		p, _ := principalOf(r)
		us, err := s.auth.List(p)
		if err != nil {
			s.authError(w, err)
			return
		}
		jsonOut(w, 200, map[string]any{"users": us})

	case path == "users" && post:
		p, _ := principalOf(r)
		var in struct{ Name, Display, Password, Role string }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			fail(w, 400, "bad JSON")
			return
		}
		u, err := s.auth.AddUser(p, in.Name, in.Display, in.Password, auth.Role(in.Role))
		if err != nil {
			s.authError(w, err)
			return
		}
		jsonOut(w, 201, u)

	case strings.HasPrefix(path, "users/") && post:
		p, _ := principalOf(r)
		parts := strings.Split(path, "/")
		if len(parts) != 3 {
			fail(w, 404, "no such route")
			return
		}
		var err error
		switch parts[2] {
		case "disable", "enable":
			err = s.auth.SetDisabled(p, parts[1], parts[2] == "disable")
		case "password":
			var in struct{ Password string }
			if json.NewDecoder(r.Body).Decode(&in) != nil {
				fail(w, 400, "bad JSON")
				return
			}
			err = s.auth.ResetPassword(p, parts[1], in.Password)
		default:
			fail(w, 404, "no such route")
			return
		}
		if err != nil {
			s.authError(w, err)
			return
		}
		jsonOut(w, 200, map[string]string{"status": "done"})

	case path == "audit" && r.Method == http.MethodGet:
		p, _ := principalOf(r)
		if p.Role != auth.Admin {
			fail(w, 403, auth.ErrForbidden.Error())
			return
		}
		es := s.auth.Audit().Entries()
		status := "verified"
		if err := audit.VerifyEntries(es); err != nil {
			status = "BROKEN: " + err.Error()
		}
		n := len(es)
		if len(es) > 100 {
			es = es[len(es)-100:]
		}
		jsonOut(w, 200, map[string]any{"status": status, "count": n, "entries": es})

	default:
		fail(w, 404, "no route "+r.Method+" "+r.URL.Path)
	}
}

func (s *server) startSession(w http.ResponseWriter, r *http.Request, name, pw string) {
	tok, p, err := s.auth.Login(name, pw, clientIP(r))
	if err != nil {
		s.authError(w, err)
		return
	}
	setSession(w, r, tok, 12*3600)
	jsonOut(w, 200, authState{User: &p, MinPassword: 10})
}
