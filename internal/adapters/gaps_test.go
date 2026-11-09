package adapters

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

func stubNmap(t *testing.T) string {
	dir := t.TempDir()
	args := filepath.Join(dir, "args.txt")
	var name, content string
	if runtime.GOOS == "windows" {
		// Windows exec.LookPath never matches a bare extensionless name - it only
		// tries PATHEXT suffixes (.com/.exe/.bat/.cmd) - so the stub needs a real
		// batch extension, or "nmap" silently resolves to any real nmap.exe on PATH.
		name = "nmap.bat"
		content = "@echo off\r\necho %* > \"" + args + "\"\r\necho ^<nmaprun^>^</nmaprun^>\r\n"
	} else {
		name = "nmap"
		content = "#!/bin/sh\necho \"$@\" > " + args + "\necho '<nmaprun></nmaprun>'\n"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	// os.PathListSeparator is ":" on Unix and ";" on Windows - a hardcoded ":" here
	// would silently fuse dir into the next PATH entry on Windows and never match.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return args
}

func TestGap_NmapIgnoresPortAllowList(t *testing.T) {
	args := stubNmap(t)
	only80 := func(p int) bool { return p == 80 }
	_, err := (&Nmap{}).Run(context.Background(), Job{Host: "127.0.0.1", Options: map[string]string{}, AllowPort: only80, AllowedPorts: []int{80}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(args)
	if !strings.Contains(string(b), "-p 80") || strings.Contains(string(b), "--top-ports") {
		t.Errorf("SCOPE LEAK: scope allows only port 80 but nmap was invoked as: nmap %s", strings.TrimSpace(string(b)))
	}
}

func TestGap_NmapIgnoresRateLimit(t *testing.T) {
	args := stubNmap(t)
	_, _ = (&Nmap{}).Run(context.Background(), Job{Host: "127.0.0.1", Options: map[string]string{}, Limiter: scope.NewLimiter(5), MaxReqPerSec: 5})
	b, _ := os.ReadFile(args)
	if !strings.Contains(string(b), "--max-rate") {
		t.Errorf("RATE LIMIT NOT APPLIED: max_req_per_sec=5 never reaches nmap: nmap %s", strings.TrimSpace(string(b)))
	}
}

func TestGap_RunCmdHangsOnChildProcess(t *testing.T) {
	start := time.Now()
	_, _, _ = runCmd(context.Background(), 1*time.Second, "sh", "-c", "sleep 8 & wait")
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("HANG: a 1s timeout took %v because an orphaned child kept the output pipe open", el.Round(time.Millisecond))
	}
}

// A name that passes the plan-time guard check must still be refused if it is rebound at connect time.
func TestRebindingBlockedAtDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	j := Job{Host: "localhost", DialCheck: func(host string, ip net.IP) error { return errors.New("rebound outside scope") }}
	if s := probe(context.Background(), j, port); s.State == "open" {
		t.Errorf("connection was made even though DialCheck refused the address")
	}
	j.DialCheck = func(string, net.IP) error { return nil }
	if s := probe(context.Background(), j, port); s.State != "open" {
		t.Errorf("DialCheck=nil-error must still allow the connection, got %q", s.State)
	}
}

// stubTool creates a fake executable named <tool> on PATH that records the
// arguments it was invoked with to a file, and returns that file's path. It
// writes nothing else - adapters that parse real stdout/output-file content
// (like Nmap's XML) need their own richer stub; this one only proves which
// flags reached the command line, which is all these gap tests need.
func stubTool(t *testing.T, tool string) string {
	dir := t.TempDir()
	args := filepath.Join(dir, "args.txt")
	var name, content string
	if runtime.GOOS == "windows" {
		name = tool + ".bat"
		content = "@echo off\r\necho %* > \"" + args + "\"\r\n"
	} else {
		name = tool
		content = "#!/bin/sh\necho \"$@\" > " + args + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return args
}

func TestGap_MetasploitIgnoresPortAllowList(t *testing.T) {
	args := stubTool(t, "msfconsole")
	only80 := func(p int) bool { return p == 80 }
	_, err := (&Metasploit{}).Run(context.Background(), Job{
		Host: "127.0.0.1", Port: 4444,
		Options:   map[string]string{"module": "auxiliary/scanner/http/http_version"},
		AllowPort: only80,
	})
	if err == nil {
		b, _ := os.ReadFile(args)
		t.Errorf("SCOPE LEAK: scope allows only port 80 but metasploit ran unrejected: msfconsole %s", strings.TrimSpace(string(b)))
	}
}

func TestGap_NiktoIgnoresPortAllowList(t *testing.T) {
	args := stubTool(t, "nikto")
	only8443 := func(p int) bool { return p == 8443 }
	_, _ = (&Nikto{}).Run(context.Background(), Job{Host: "127.0.0.1", Port: 80, AllowPort: only8443})
	if _, err := os.Stat(args); err == nil {
		t.Error("SCOPE LEAK: scope allows only port 8443 but nikto ran against port 80 anyway")
	}
}

func TestGap_NiktoIgnoresRateLimit(t *testing.T) {
	args := stubTool(t, "nikto")
	_, _ = (&Nikto{}).Run(context.Background(), Job{Host: "127.0.0.1", Port: 80, MaxReqPerSec: 5})
	b, _ := os.ReadFile(args)
	if !strings.Contains(string(b), "-Pause") {
		t.Errorf("RATE LIMIT NOT APPLIED: max_req_per_sec=5 never reaches nikto: nikto %s", strings.TrimSpace(string(b)))
	}
}

func TestGap_ZAPIgnoresPortAllowList(t *testing.T) {
	var hit int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hit, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "status"):
			w.Write([]byte(`{"status":"100"}`))
		case strings.Contains(r.URL.Path, "alerts"):
			w.Write([]byte(`{"alerts":[]}`))
		default:
			w.Write([]byte(`{"Result":"OK","scan":"0"}`))
		}
	}))
	defer srv.Close()
	t.Setenv("ZAP_URL", srv.URL)

	only80 := func(p int) bool { return p == 80 }
	_, err := (&ZAP{}).Run(context.Background(), Job{Target: "127.0.0.1:9999", Host: "127.0.0.1", AllowPort: only80})
	if err == nil || atomic.LoadInt32(&hit) > 0 {
		t.Errorf("SCOPE LEAK: scope allows only port 80 but ZAP was invoked against port 9999 (requests reaching daemon: %d, err=%v)", hit, err)
	}
}
