// Command vapt serves the analyst console and API on localhost.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/adapters"
	"github.com/ayanasarkar/vapt-agent/internal/agent"
	"github.com/ayanasarkar/vapt-agent/internal/auth"
	"github.com/ayanasarkar/vapt-agent/internal/llm"
	"github.com/ayanasarkar/vapt-agent/internal/report"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

//go:embed web
var webFS embed.FS

type server struct {
	env        agent.Env
	listenHost string
	token      string
	auth       *auth.Store
	mu         sync.Mutex
	items      map[string]*agent.Assessment
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address (keep it on loopback)")
	data := flag.String("data", "data", "directory for assessments (raw output, audit logs, state)")
	flag.Parse()
	if err := os.MkdirAll(*data, 0o700); err != nil {
		log.Fatal(err)
	}
	tok := make([]byte, 16)
	rand.Read(tok)
	st, err := auth.Open(filepath.Join(*data, "auth"), auth.Options{})
	if err != nil {
		log.Fatalf("accounts: %v", err)
	}
	s := &server{env: agent.Env{DataDir: *data, Reg: adapters.NewRegistry(), LLM: llm.FromEnv()}, token: hex.EncodeToString(tok), auth: st, items: map[string]*agent.Assessment{}}
	s.listenHost = hostOnly(*addr)
	// Scripted runs (demo.sh, CI) can create the first administrator from the environment. Interactive use does it in the console.
	if u, p := os.Getenv("KAVACH_ADMIN_USER"), os.Getenv("KAVACH_ADMIN_PASSWORD"); u != "" && p != "" && !st.HasUsers() {
		if _, err := st.Setup(u, "", p); err != nil {
			log.Fatalf("KAVACH_ADMIN_USER/KAVACH_ADMIN_PASSWORD: %v", err)
		}
		log.Printf("accounts: created administrator %q from the environment", auth.NormName(u))
	}
	if h := s.listenHost; !(h == "127.0.0.1" || h == "localhost" || h == "::1") {
		log.Printf("WARNING: listening on %q, not loopback. Sessions travel over plain HTTP; put a TLS proxy in front or use loopback.", h)
	}
	if st.HasUsers() {
		log.Printf("accounts: sign in at the console with an existing account")
	} else {
		log.Printf("accounts: none yet. Open the console from this machine to create the first administrator")
	}
	log.Printf("vapt-agent console: http://%s   model: %s", *addr, s.env.LLM.Name())
	srv := &http.Server{Addr: *addr, Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	page := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { http.ServeFileFS(w, r, sub, name) }
	}
	mux.HandleFunc("/{$}", page("landing.html"))
	mux.HandleFunc("/console", page("chat.html"))
	mux.HandleFunc("/workbench", page("console.html"))
	mux.HandleFunc("/api/auth/", s.authAPI)
	mux.HandleFunc("/api/config", s.config)
	mux.HandleFunc("/api/assessments", s.create)
	mux.HandleFunc("/api/guard-check", s.guardCheck)
	mux.HandleFunc("/api/lab-status", s.labStatus)
	mux.HandleFunc("/api/assessments/", s.item)
	return s.protect(s.gate(mux))
}

// protect defends the loopback console against DNS rebinding and cross-site requests. A web page on
// another origin can make the browser send requests to 127.0.0.1 (or rebind its own name to it); without
// these checks it could read /api/config (which carries the session token) and then drive scans.
// 1) The Host header must be this machine (loopback name/IP, or the address we were told to listen on).
// 2) A request carrying an Origin header must be same-origin.
func (s *server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Host
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
		h = strings.Trim(strings.ToLower(h), "[]")
		if !(h == "127.0.0.1" || h == "localhost" || h == "::1" || (s.listenHost != "" && h == strings.ToLower(s.listenHost))) {
			fail(w, 403, "unexpected Host header: this console only answers requests addressed to the local machine")
			return
		}
		w.Header().Set("X-Frame-Options", "DENY") // the approval buttons must never be framed by another page
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if o := r.Header.Get("Origin"); o != "" {
			if u, err := url.Parse(o); err != nil || !strings.EqualFold(u.Host, r.Host) {
				fail(w, 403, "cross-origin request refused")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	jsonOut(w, code, map[string]string{"error": msg})
}

func (s *server) config(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, 200, map[string]any{"token": s.token, "model": s.env.LLM.Name(), "data_leaves_machine": llm.DataLeaves(s.env.LLM), "matrix": report.Matrix(s.env.Reg)})
}

func (s *server) authed(w http.ResponseWriter, r *http.Request) bool {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-VAPT-Token")), []byte(s.token)) != 1 {
		fail(w, 403, "missing or bad X-VAPT-Token")
		return false
	}
	return true
}

type createReq struct {
	Name              string            `json:"name"`
	Authorization     string            `json:"authorization"`
	Request           string            `json:"request"`
	Targets           []string          `json:"targets"`
	AuthorizedDomains []string          `json:"authorized_domains"`
	Exclusions        []string          `json:"exclusions"`
	Hosts             []string          `json:"hosts"`
	Ports             []int             `json:"ports"`
	AllowedTools      []string          `json:"allowed_tools"`
	AllowActive       bool              `json:"allow_active"`
	AllowExploit      bool              `json:"allow_exploit"`
	AllowNonLab       bool              `json:"allow_non_lab"`
	MaxReqPerSec      int               `json:"max_req_per_sec"`
	Criticality       map[string]string `json:"criticality"`
	AutoApprove       bool              `json:"auto_approve"`
}

func (s *server) create(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" { // history for this run of the server, newest first
		if !s.authed(w, r) {
			return
		}
		type row struct {
			ID       string    `json:"id"`
			Name     string    `json:"name"`
			Request  string    `json:"request"`
			Phase    string    `json:"phase"`
			Created  time.Time `json:"created"`
			Findings int       `json:"findings"`
		}
		rows := []row{}
		s.mu.Lock()
		for _, a := range s.items {
			a.Lock()
			rows = append(rows, row{a.ID, a.Scope.Name, a.Request, a.Phase, a.Created, len(a.Findings)})
			a.Unlock()
		}
		s.mu.Unlock()
		sort.Slice(rows, func(i, j int) bool { return rows[i].Created.After(rows[j].Created) })
		if len(rows) > 40 {
			rows = rows[:40]
		}
		jsonOut(w, 200, map[string]any{"assessments": rows})
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "GET or POST only")
		return
	}
	if !s.authed(w, r) {
		return
	}
	if _, ok := actor(w, r); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var c createReq
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		fail(w, 400, "bad JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(c.Request) == "" {
		fail(w, 400, "write an assessment request")
		return
	}
	if len(c.Hosts) == 0 {
		for _, t := range c.Targets {
			if !strings.Contains(t, "/") {
				c.Hosts = append(c.Hosts, t)
			}
		}
	}
	sfx := make([]byte, 2)
	rand.Read(sfx)
	id := time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(sfx) // two creates in one second must not share a directory
	sc := scope.Scope{Name: orS(c.Name, "unnamed lab scope"), Authorization: c.Authorization, Targets: c.Targets, AuthorizedDomains: c.AuthorizedDomains, Exclusions: c.Exclusions, Ports: c.Ports,
		AllowedTools: c.AllowedTools, AllowActive: c.AllowActive, AllowExploit: c.AllowExploit, AllowNonLab: c.AllowNonLab, MaxReqPerSec: c.MaxReqPerSec}
	a, err := agent.New(s.env, id, c.Request, sc, c.Hosts, c.Criticality, c.AutoApprove)
	if err != nil {
		fail(w, 422, err.Error())
		return
	}
	if p, ok := principalOf(r); ok {
		a.Attribute(p.Name, string(p.Role))
	}
	s.mu.Lock()
	s.items[id] = a
	s.mu.Unlock()
	jsonOut(w, 201, map[string]string{"id": id})
}

func orS(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func (s *server) item(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/assessments/"), "/"), "/")
	s.mu.Lock()
	a := s.items[parts[0]]
	s.mu.Unlock()
	if a == nil {
		fail(w, 404, "unknown assessment")
		return
	}
	act := ""
	if len(parts) > 1 {
		act = parts[1]
	}
	if r.Method == "POST" && !s.authed(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 80<<20)
	switch {
	case act == "" && r.Method == "GET":
		a.Lock()
		es, st := a.AuditEntries()
		b, _ := json.Marshal(map[string]any{"assessment": a, "audit_status": st, "audit_count": len(es), "matrix": report.Matrix(a.Registry())})
		a.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	case act == "start" && r.Method == "POST":
		a.Start()
		jsonOut(w, 202, map[string]string{"status": "started"})
	case act == "approve" && r.Method == "POST":
		who, ok := actor(w, r)
		if !ok {
			return
		}
		var b struct {
			Steps []string `json:"steps"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		if err := a.ApprovePlan(b.Steps, who); err != nil {
			fail(w, 409, err.Error())
			return
		}
		jsonOut(w, 202, map[string]string{"status": "approved"})
	case act == "deny" && r.Method == "POST":
		who, ok := actor(w, r)
		if !ok {
			return
		}
		var b struct {
			Reason string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		if err := a.DenyPlan(who, b.Reason); err != nil {
			fail(w, 409, err.Error())
			return
		}
		jsonOut(w, 202, map[string]string{"status": "denied"})
	case act == "chat" && r.Method == "POST":
		var b struct {
			Message string `json:"message"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		if strings.TrimSpace(b.Message) == "" {
			fail(w, 400, "empty message")
			return
		}
		jsonOut(w, 200, a.ChatDetailed(r.Context(), b.Message))
	case act == "proof" && r.Method == "GET":
		pv, err := a.Proof(r.URL.Query().Get("finding"))
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		jsonOut(w, 200, map[string]any{"proof": pv, "score_meaning": "evidence-strength score computed by code; not a calibrated probability"})
	case act == "validate" && r.Method == "POST":
		who, ok := actor(w, r)
		if !ok {
			return
		}
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		ap, err := a.RequestValidation(in["finding_id"], in["module"], who)
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
		jsonOut(w, 201, ap)
	case act == "decide" && r.Method == "POST":
		who, ok := actor(w, r)
		if !ok {
			return
		}
		var in struct {
			ApprovalID    string `json:"approval_id"`
			Approve       bool   `json:"approve"`
			Reason        string `json:"reason"`
			ConfirmTarget string `json:"confirm_target"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		if err := a.Decide(in.ApprovalID, in.Approve, who, in.Reason, in.ConfirmTarget); err != nil {
			fail(w, 422, err.Error())
			return
		}
		jsonOut(w, 202, map[string]string{"status": "recorded"})
	case act == "import" && r.Method == "POST":
		if err := r.ParseMultipartForm(80 << 20); err != nil {
			fail(w, 400, err.Error())
			return
		}
		tool := r.FormValue("tool")
		if ad, ok := a.Registry().Get(tool); !ok || ad.Mode() != adapters.ImportOnl || !safeName.MatchString(tool) {
			fail(w, 422, "tool must be one of the import-only integrations")
			return
		}
		f, hdr, err := r.FormFile("file")
		if err != nil {
			fail(w, 400, "file missing")
			return
		}
		defer f.Close()
		dir := filepath.Join(a.Dir(), "imports")
		os.MkdirAll(dir, 0o700)
		name := tool + "-" + safeBase(hdr.Filename)
		p := filepath.Join(dir, name)
		out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		io.Copy(out, io.LimitReader(f, 64<<20))
		out.Close()
		if err := a.AddImport(tool, p); err != nil {
			fail(w, 422, err.Error())
			return
		}
		jsonOut(w, 201, map[string]string{"stored": name})
	case act == "stop" && r.Method == "POST":
		a.Cancel()
		jsonOut(w, 200, map[string]string{"status": "stopping"})
	case act == "audit" && r.Method == "GET":
		es, st := a.AuditEntries()
		jsonOut(w, 200, map[string]any{"status": st, "entries": es})
	case act == "report.pdf" && r.Method == "GET":
		b := report.Build(a)
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="vapt-report-`+a.ID+`.pdf"`)
		w.Write(b)
	case act == "raw" && len(parts) == 3 && r.Method == "GET":
		if !safeName.MatchString(parts[2]) {
			fail(w, 400, "bad file name")
			return
		}
		b, err := os.ReadFile(filepath.Join(a.Dir(), "raw", parts[2]))
		if err != nil {
			fail(w, 404, "no such raw file")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(b)
	default:
		fail(w, 404, fmt.Sprintf("no route %s %s", r.Method, r.URL.Path))
	}
}

func safeBase(n string) string {
	n = filepath.Base(n)
	n = regexp.MustCompile(`[^A-Za-z0-9._-]`).ReplaceAllString(n, "_")
	if n == "" || n == "." {
		return "upload"
	}
	return n
}

// guardCheck is a dry run of the scope guard. With assessment_id it asks that
// assessment's guard and writes an audit entry; without it, it validates the
// posted scope from the form and reports a verdict per target. Nothing runs.
func (s *server) guardCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "POST only")
		return
	}
	if !s.authed(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var in struct {
		createReq
		AssessmentID string   `json:"assessment_id"`
		Check        []string `json:"check"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "bad JSON: "+err.Error())
		return
	}
	if len(in.Check) > 50 {
		in.Check = in.Check[:50]
	}
	type verdict struct {
		Target  string `json:"target"`
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	who, _ := actor(w, r)
	if who == "" {
		return
	}
	var out []verdict
	if in.AssessmentID != "" {
		s.mu.Lock()
		a := s.items[in.AssessmentID]
		s.mu.Unlock()
		if a == nil {
			fail(w, 404, "unknown assessment")
			return
		}
		for _, t := range in.Check {
			d := a.Probe(t, who)
			out = append(out, verdict{t, d.Allowed, d.Reason})
		}
		jsonOut(w, 200, map[string]any{"verdicts": out})
		return
	}
	g, err := scope.New(scope.Scope{Name: in.Name, Authorization: orS(in.Authorization, "preview"), Targets: in.Targets, AuthorizedDomains: in.AuthorizedDomains, Exclusions: in.Exclusions, Ports: in.Ports,
		AllowedTools: in.AllowedTools, AllowActive: in.AllowActive, AllowExploit: in.AllowExploit, AllowNonLab: in.AllowNonLab})
	if err != nil {
		jsonOut(w, 200, map[string]any{"scope_error": err.Error(), "verdicts": []verdict{}})
		return
	}
	for _, t := range in.Check {
		d := g.Check(scope.Action{Tool: "probe", Target: t, Kind: scope.KindPassive})
		out = append(out, verdict{t, d.Allowed, d.Reason})
	}
	jsonOut(w, 200, map[string]any{"verdicts": out})
}

// labPorts are the ports cmd/lab tries, in order, for each service. labStatus reports which of them accept a TCP
// connection on 127.0.0.1 so the console can say whether the lab is running. It dials loopback only, sends nothing
// and reads nothing; it is a status light for the UI, not an agent action.
var labPorts = map[string][]int{"web": {8081, 8088, 8888, 8000, 9090, 5000, 8008, 3000, 9000}, "ftp": {2121, 2222}, "telnet": {2323, 23}}

func (s *server) labStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string][]int{}
	for svc := range labPorts { // fill the map before any goroutine starts: they only append under mu
		out[svc] = []int{}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for svc, ports := range labPorts {
		for _, p := range ports {
			wg.Add(1)
			go func(svc string, p int) {
				defer wg.Done()
				c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)), 400*time.Millisecond)
				if err != nil {
					return
				}
				c.Close()
				mu.Lock()
				out[svc] = append(out[svc], p)
				mu.Unlock()
			}(svc, p)
		}
	}
	wg.Wait()
	for k := range out {
		sort.Ints(out[k])
	}
	jsonOut(w, 200, out)
}
