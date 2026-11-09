package adapters

// NOTE: the XML documents below are minimal PARSER FIXTURES that exercise the
// import code paths. They are not scan results and are never shipped as demo data.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "x.xml")
	os.WriteFile(p, []byte(body), 0o600)
	return p
}

func TestNessusParser(t *testing.T) {
	p := write(t, `<?xml version="1.0"?><NessusClientData_v2><Report name="r"><ReportHost name="10.0.0.5"><ReportItem port="80" svc_name="www" protocol="tcp" severity="3" pluginID="1234" pluginName="Test plugin"><synopsis>syn</synopsis><description>desc CWE-79</description><solution>patch</solution><cvss3_base_score>8.1</cvss3_base_score><cve>CVE-2021-0001</cve><cve>CVE-2021-0001</cve><exploit_available>true</exploit_available><plugin_output>out</plugin_output></ReportItem></ReportHost></Report></NessusClientData_v2>`)
	res, err := (&Nessus{}).Run(context.Background(), Job{ImportPath: p})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("err=%v n=%d", err, len(res.Findings))
	}
	f := res.Findings[0]
	if f.Host != "10.0.0.5" || f.Port != 80 || f.Severity != "high" || f.CVSS == nil || *f.CVSS != 8.1 || len(f.CVEs) != 1 || f.ExploitAvail == nil || !*f.ExploitAvail {
		t.Errorf("bad parse: %+v", f)
	}
	if !strings.Contains(f.RawRef, "plugin 1234") {
		t.Errorf("raw ref %q", f.RawRef)
	}
}

func TestOpenVASParser(t *testing.T) {
	p := write(t, `<report><results><result id="r1"><name>Thing</name><host>10.0.0.5<asset asset_id="a"/></host><port>443/tcp</port><nvt oid="1.2.3"><cvss_base>5.0</cvss_base><refs><ref type="cve" id="CVE-2020-9999"/></refs><solution>fix</solution></nvt><severity>5.0</severity><qod><value>80</value></qod><description>d</description></result></results></report>`)
	res, err := (&OpenVAS{}).Run(context.Background(), Job{ImportPath: p})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("err=%v", err)
	}
	f := res.Findings[0]
	if f.Host != "10.0.0.5" || f.Port != 443 || f.CVSS == nil || *f.CVSS != 5.0 || f.ToolConf == nil || *f.ToolConf != 0.8 || f.Severity != "medium" {
		t.Errorf("bad parse: %+v", f)
	}
}

func TestBurpParser(t *testing.T) {
	p := write(t, `<issues><issue><serialNumber>42</serialNumber><name>Cookie without HttpOnly flag set</name><host ip="10.0.0.5">http://10.0.0.5:8081</host><path>/</path><severity>Low</severity><confidence>Certain</confidence><issueDetail>d</issueDetail><remediationBackground>fix</remediationBackground></issue></issues>`)
	res, err := (&Burp{}).Run(context.Background(), Job{ImportPath: p})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("err=%v", err)
	}
	f := res.Findings[0]
	if f.Port != 8081 || f.Key != "web:cookie-httponly" || f.Severity != "low" || *f.ToolConf != 0.95 {
		t.Errorf("bad parse: %+v", f)
	}
}

func TestImportRejectsWrongFormatAndDoesNotExpandEntities(t *testing.T) {
	if _, err := (&Nessus{}).Run(context.Background(), Job{ImportPath: write(t, "<foo/>")}); err == nil {
		t.Error("wrong format accepted")
	}
	xxe := `<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><issues><issue><serialNumber>1</serialNumber><name>n &x;</name><host>h</host><severity>Low</severity><confidence>Firm</confidence></issue></issues>`
	res, _ := (&Burp{}).Run(context.Background(), Job{ImportPath: write(t, xxe)})
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "root:") {
			t.Fatal("external entity was expanded (XXE)")
		}
	}
}

func TestNormalizeKeyCorrelatesAcrossTools(t *testing.T) {
	cases := map[string]string{
		"Anti-clickjacking Header":                     "web:missing-header:x-frame-options",
		"The X-Content-Type-Options header is not set": "web:missing-header:x-content-type-options",
		"Content Security Policy (CSP) Header Not Set": "web:missing-header:content-security-policy",
		"Directory indexing found":                     "web:directory-listing",
		"Cookie No HttpOnly Flag":                      "web:cookie-httponly",
	}
	for in, want := range cases {
		if got := NormalizeKey(in, ""); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
}

func TestWebCheckAgainstLocalServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "Test/9.9")
		http.SetCookie(w, &http.Cookie{Name: "s", Value: "secretvalue"})
		fmt.Fprint(w, `<html><title>t</title><input type="password"></html>`)
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "DB_PASSWORD=hunter2\n") })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := (&WebCheck{}).Run(context.Background(), Job{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, f := range res.Findings {
		keys[f.Key] = f.Excerpt
	}
	for _, want := range []string{"web:missing-header:content-security-policy", "web:cookie-httponly", "web:cleartext-credentials", "web:exposed-env", "web:version-disclosure:server"} {
		if _, ok := keys[want]; !ok {
			t.Errorf("missing finding %s (got %v)", want, keys)
		}
	}
	for k, ex := range keys {
		if strings.Contains(ex, "hunter2") || strings.Contains(ex, "secretvalue") {
			t.Errorf("secret leaked into evidence for %s: %q", k, ex)
		}
	}
}

func TestWebCheckSoft404NoFalsePositives(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, "<html><title>app</title>catch-all</html>")
	}))
	defer srv.Close()
	res, err := (&WebCheck{}).Run(context.Background(), Job{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("soft-404 catch-all produced findings: %+v", res.Findings)
	}
}

func TestPortScanFindsOpenAndClosedWithBanner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Server", "X/1"); fmt.Fprint(w, "ok") }))
	defer srv.Close()
	var port int
	fmt.Sscanf(srv.URL[strings.LastIndex(srv.URL, ":")+1:], "%d", &port)
	res, err := (&PortScan{}).Run(context.Background(), Job{Host: "127.0.0.1", Options: map[string]string{"ports": fmt.Sprintf("%d,1", port)}})
	if err != nil {
		t.Fatal(err)
	}
	st := map[int]string{}
	for _, s := range res.Services {
		st[s.Port] = s.State
	}
	if st[port] != "open" || st[1] == "open" {
		t.Errorf("states: %v", st)
	}
}

func TestUnsafeHostRejectedBeforeExec(t *testing.T) {
	for _, h := range []string{"-oN/tmp/x", "a b", "$(id)", ""} {
		if validHost(h) == nil {
			t.Errorf("host %q accepted", h)
		}
	}
	if _, err := (&Nmap{}).Run(context.Background(), Job{Host: "-oX"}); err == nil {
		t.Error("nmap ran with option-like host")
	}
}

func TestMetasploitRejectsBadModulesAndPayloads(t *testing.T) {
	for _, m := range []string{"", "exploit/x; exit", "payload/linux/x", "../../etc"} {
		if _, err := (&Metasploit{}).Run(context.Background(), Job{Host: "127.0.0.1", Options: map[string]string{"module": m}}); err == nil {
			t.Errorf("module %q accepted", m)
		}
	}
}
