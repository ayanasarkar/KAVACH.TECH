package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// ZAP drives a running OWASP ZAP daemon through its REST API
// (ZAP_URL, default http://127.0.0.1:8090; ZAP_API_KEY optional).
type ZAP struct{}

func (*ZAP) Name() string     { return "zap" }
func (*ZAP) Mode() Mode       { return Live }
func (*ZAP) Kind() scope.Kind { return scope.KindActive }
func (*ZAP) Describe() string {
	return "Web app/API scanning through the OWASP ZAP REST API: spider, optional active scan, alert import."
}

func zapBase() string {
	if u := os.Getenv("ZAP_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://127.0.0.1:8090"
}

func zapCall(ctx context.Context, path string, q url.Values) (map[string]any, error) {
	if k := os.Getenv("ZAP_API_KEY"); k != "" {
		q.Set("apikey", k)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", zapBase()+path+"?"+q.Encode(), nil)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ZAP API %s -> %d: %s", path, resp.StatusCode, clip(string(b), 200))
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (*ZAP) Available() (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := zapCall(ctx, "/JSON/core/view/version/", url.Values{}); err != nil {
		return false, "ZAP daemon not reachable at " + zapBase() + " (start `zap.sh -daemon -port 8090` and set ZAP_URL / ZAP_API_KEY)"
	}
	return true, ""
}

func str(m map[string]any, k string) string { v, _ := m[k].(string); return v }

// portOf returns a URL's effective port: its explicit port if present,
// otherwise 443 for https and 80 for everything else.
func portOf(u *url.URL) int {
	if p := u.Port(); p != "" {
		var port int
		fmt.Sscanf(p, "%d", &port)
		return port
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

func (*ZAP) Run(ctx context.Context, j Job) (Result, error) {
	target := j.Target
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	bu, perr := url.Parse(target)
	if perr != nil {
		return Result{}, fmt.Errorf("invalid ZAP target %q: %w", target, perr)
	}
	port := portOf(bu)
	if j.AllowPort != nil && !j.AllowPort(port) {
		return Result{}, fmt.Errorf("port %d is not in the authorised port list", port)
	}
	if _, err := zapCall(ctx, "/JSON/core/action/accessUrl/", url.Values{"url": {target}}); err != nil {
		return Result{}, err
	}
	poll := func(path, idKey string, id string) error {
		deadline := time.Now().Add(8 * time.Minute)
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			m, err := zapCall(ctx, path, url.Values{idKey: {id}})
			if err != nil {
				return err
			}
			if str(m, "status") == "100" {
				return nil
			}
		}
		return fmt.Errorf("ZAP job %s timed out", path)
	}
	m, err := zapCall(ctx, "/JSON/spider/action/scan/", url.Values{"url": {target}, "recurse": {"true"}, "maxChildren": {"30"}})
	if err != nil {
		return Result{}, err
	}
	if err := poll("/JSON/spider/view/status/", "scanId", str(m, "scan")); err != nil {
		return Result{}, err
	}
	if j.Options["active"] == "true" {
		m, err := zapCall(ctx, "/JSON/ascan/action/scan/", url.Values{"url": {target}, "recurse": {"true"}})
		if err != nil {
			return Result{}, err
		}
		if err := poll("/JSON/ascan/view/status/", "scanId", str(m, "scan")); err != nil {
			return Result{}, err
		}
	}
	m, err = zapCall(ctx, "/JSON/core/view/alerts/", url.Values{"baseurl": {target}, "start": {"0"}, "count": {"500"}})
	if err != nil {
		return Result{}, err
	}
	rawb, _ := json.MarshalIndent(m, "", "  ")
	res := Result{Raw: string(rawb)}
	alerts, _ := m["alerts"].([]any)
	conf := map[string]float64{"User Confirmed": 0.95, "High": 0.8, "Medium": 0.6, "Low": 0.35}
	sev := map[string]string{"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
	for _, a := range alerts {
		am, _ := a.(map[string]any)
		cf := str(am, "confidence")
		if cf == "False Positive" {
			continue
		}
		name := str(am, "alert")
		if name == "" {
			name = str(am, "name")
		}
		key := NormalizeKey(name, str(am, "url"))
		if key == "" {
			key = "zap:" + str(am, "pluginId") + ":" + str(am, "param")
		}
		var cwes []string
		if c := str(am, "cweid"); c != "" && c != "-1" && c != "0" {
			cwes = []string{"CWE-" + c}
		}
		c := conf[cf]
		// Attribute the alert to the host it was actually raised on. If the spider followed a link off the
		// target, that host goes through the scope guard in ingest and is discarded and audited, not hidden.
		ah, ap := j.Host, port
		if au, e := url.Parse(str(am, "url")); e == nil && au.Hostname() != "" {
			ah = au.Hostname()
			ap = portOf(au)
		}
		res.Findings = append(res.Findings, model.RawFinding{Tool: "zap", Key: key, Title: name, Description: clip(str(am, "description"), 600),
			Host: ah, Port: ap, Proto: "tcp", Severity: sev[str(am, "risk")], Basis: model.BasisReported, ToolConf: &c, CWEs: cwes,
			Remediation: clip(str(am, "solution"), 500), References: strings.Fields(str(am, "reference")),
			Excerpt: fmt.Sprintf("%s (plugin %s) at %s evidence=%q", name, str(am, "pluginId"), str(am, "url"), clip(str(am, "evidence"), 160)),
			RawRef:  "zap alert pluginId " + str(am, "pluginId")})
	}
	res.Summary = fmt.Sprintf("%d ZAP alerts", len(res.Findings))
	return res, nil
}
