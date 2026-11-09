package adapters

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/model"
	"github.com/ayanasarkar/vapt-agent/internal/scope"
)

// Nikto runs the real nikto binary and parses its XML report.
type Nikto struct{}

func (*Nikto) Name() string     { return "nikto" }
func (*Nikto) Mode() Mode       { return Live }
func (*Nikto) Kind() scope.Kind { return scope.KindActive }
func (*Nikto) Describe() string {
	return "Web server configuration and known-issue checks via the nikto CLI (XML output)."
}
func (*Nikto) Available() (bool, string) { return have("nikto") }

type niktoScan struct {
	Details []struct {
		Port  int    `xml:"targetport,attr"`
		Host  string `xml:"targethostname,attr"`
		IP    string `xml:"targetip,attr"`
		Items []struct {
			ID     string `xml:"id,attr"`
			Method string `xml:"method,attr"`
			Desc   string `xml:"description"`
			URI    string `xml:"uri"`
		} `xml:"item"`
	} `xml:"scandetails"`
}

func (*Nikto) Run(ctx context.Context, j Job) (Result, error) {
	if err := validHost(j.Host); err != nil {
		return Result{}, err
	}
	port := j.Port
	if port == 0 {
		port = 80
	}
	if j.AllowPort != nil && !j.AllowPort(port) {
		return Result{}, fmt.Errorf("port %d is not in the authorised port list", port)
	}
	f, err := os.CreateTemp("", "nikto-*.xml")
	if err != nil {
		return Result{}, err
	}
	f.Close()
	defer os.Remove(f.Name())
	args := []string{"-h", j.Host, "-p", fmt.Sprint(port), "-Format", "xml", "-output", f.Name(), "-nointeractive", "-maxtime", "240s"}
	if strings.HasPrefix(j.Target, "https://") {
		args = append(args, "-ssl")
	}
	if j.MaxReqPerSec > 0 {
		// Nikto has no request-rate flag; -Pause inserts a fixed delay (seconds)
		// between each test, approximating the scope's requests-per-second cap.
		args = append(args, "-Pause", fmt.Sprintf("%.3f", 1/float64(j.MaxReqPerSec)))
	}
	so, se, runErr := runCmd(ctx, 5*time.Minute, "nikto", args...)
	b, _ := os.ReadFile(f.Name())
	if len(b) == 0 {
		if runErr == nil {
			runErr = fmt.Errorf("nikto produced no report")
		}
		return Result{Raw: so + se}, runErr
	}
	var scan niktoScan
	if e := xml.Unmarshal(b, &scan); e != nil {
		return Result{Raw: string(b)}, fmt.Errorf("could not parse nikto XML: %w", e)
	}
	res := Result{Raw: string(b)}
	for _, d := range scan.Details {
		for _, it := range d.Items {
			desc := strings.TrimSpace(it.Desc)
			key := NormalizeKey(desc, it.URI)
			if key == "" {
				key = "nikto:item:" + it.ID + ":" + it.URI
			}
			res.Findings = append(res.Findings, model.RawFinding{Tool: "nikto", Key: key, Title: clip(desc, 110), Host: j.Host, Port: port, Proto: "tcp",
				Severity: "low", Basis: model.BasisReported, CVEs: FindCVEs(desc),
				Description: desc + " (Nikto does not rate severity; 'low' is a nominal placeholder, review manually.)",
				Excerpt:     fmt.Sprintf("%s %s: %s", it.Method, it.URI, clip(desc, 300)), RawRef: "nikto item id " + it.ID})
		}
	}
	res.Summary = fmt.Sprintf("%d nikto items", len(res.Findings))
	return res, nil
}
