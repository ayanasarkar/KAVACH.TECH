// Command lab is a deliberately weak LOCAL test target (loopback only) used to
// demonstrate the agent end to end. It is a fixture to be scanned, not scanner
// output. It refuses to bind to anything but loopback addresses.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

const spa = `<!doctype html><html><head><title>Lab SPA</title></head><body><div id="app">Lab single-page app (catch-all route)</div></body></html>`

func mustLoop(addr string) {
	h, _, _ := net.SplitHostPort(addr)
	if ip := net.ParseIP(h); ip == nil || !ip.IsLoopback() {
		log.Fatalf("lab target refuses to bind non-loopback %s", addr)
	}
}

func weakSite() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "LabHTTPd/1.0")
		w.Header().Set("X-Powered-By", "LabFramework/0.1")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "lab-demo-session"})
		fmt.Fprint(w, `<html><head><title>Lab Intranet Login</title></head><body><h1>Lab intranet</h1><form method="post" action="/login"><input name="u"><input type="password" name="p"><button>Login</button></form></body></html>`)
	})
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "LabHTTPd/1.0")
		fmt.Fprint(w, `<html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1><a href="backup.zip">backup.zip</a></body></html>`)
	})
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ref: refs/heads/main\n") })
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "# LAB DEMO VALUES ONLY\nDB_PASSWORD=lab-demo-not-a-secret\nAPI_KEY=lab-demo-not-a-secret\n")
	})
	return mux
}

// plainSite is a second, simpler weak site: no hardening headers at all.
func plainSite() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "LabLegacy/0.9")
		fmt.Fprint(w, `<html><head><title>Legacy status page</title></head><body>status: ok</body></html>`)
	})
}

func spaSite() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "LabSPA")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		fmt.Fprint(w, spa) // soft-404: every path returns 200 with the same page
	})
}

// listenAny binds the first free port from the candidates. Some systems
// (notably Windows with Hyper-V/WSL) reserve port ranges, so one fixed port
// is not reliable. All candidates are ports the agent's default scan covers.
func listenAny(host string, ports []int, what string) net.Listener {
	mustLoop(host + ":0")
	for _, p := range ports {
		l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, p))
		if err == nil {
			log.Printf("lab %-10s on %s:%d", what, host, p)
			return l
		}
		log.Printf("lab %-10s port %d unavailable (%v), trying next", what, p, err)
	}
	log.Printf("lab %-10s could not bind any of %v: skipped", what, ports)
	return nil
}

func serve(ports []int, what string, h http.Handler) {
	if l := listenAny("127.0.0.1", ports, what); l != nil {
		go func() { log.Fatal(http.Serve(l, h)) }()
	}
}

func banner(ports []int, what string, b []byte) {
	l := listenAny("127.0.0.1", ports, what)
	if l == nil {
		return
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { c.Write(b); c.Close() }()
		}
	}()
}

func main() {
	serve([]int{8081, 8088, 8888}, "weak-web", weakSite())
	serve([]int{8000, 9090, 5000}, "spa-web", spaSite())
	serve([]int{8008, 3000, 9000}, "legacy-web", plainSite())
	banner([]int{2121, 2222}, "ftp", []byte("220 LabFTP ready (anonymous allowed)\r\n"))
	banner([]int{2323, 23}, "telnet", []byte{0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03, 'L', 'a', 'b', ' ', 'l', 'o', 'g', 'i', 'n', ':', ' '})
	select {}
}

var _ = strings.TrimSpace
