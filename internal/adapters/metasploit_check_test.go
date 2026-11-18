package adapters

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestClassifyCheck(t *testing.T) {
	cases := []struct {
		name, out, want string
	}{
		{"appears vulnerable", "[+] 10.0.0.5:21 - The target appears to be vulnerable.\n", "vulnerable"},
		{"is vulnerable", "[+] 10.0.0.5:21 - The target is vulnerable.", "vulnerable"},
		{"not exploitable", "[*] 10.0.0.5:21 - The target is not exploitable.", "not_vulnerable"},
		{"not vulnerable", "[-] 10.0.0.5:21 - The target is not vulnerable.", "not_vulnerable"},
		{"cannot check", "[*] 10.0.0.5:21 - Cannot reliably check exploitability.", "undetermined"},
		{"detected only", "[*] 10.0.0.5:21 - The service is running, but could not be validated.", "undetermined"},
		{"no check support", "[*] This module does not support check.", "undetermined"},
		{"empty", "", "undetermined"},
		// The old parser called all of these not_vulnerable because they contain the substring "safe".
		{"safe checks banner", "[*] Running with safe checks enabled\n[*] Cannot reliably check exploitability.", "undetermined"},
		{"unsafe word", "[!] unsafe option SSL=false is set", "undetermined"},
		{"safe in a module path", "[*] Using auxiliary/scanner/safe_stuff", "undetermined"},
		{"safe beside a real positive", "[*] safe mode off\n[+] 10.0.0.5 - The target appears to be vulnerable.", "vulnerable"},
		{"contradiction", "[+] 10.0.0.5:21 - The target is vulnerable.\n[*] 10.0.0.6:21 - The target is not exploitable.", "undetermined"},
		{"negative first then positive", "[*] The target is not exploitable.\n[+] The target is vulnerable.", "undetermined"},
	}
	for _, c := range cases {
		if got := classifyCheck(c.out).Verdict; got != c.want {
			t.Errorf("%s: verdict = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestClassifyCheckKeepsTheSupportingLine(t *testing.T) {
	v := classifyCheck("noise\n  [+] 10.0.0.5:21 - The target appears to be vulnerable.  \nmore noise")
	if v.Line != "[+] 10.0.0.5:21 - The target appears to be vulnerable." {
		t.Fatalf("line = %q", v.Line)
	}
}

// End to end with a stand-in msfconsole on PATH, so the real Run path is exercised without Metasploit installed.
func TestMetasploitRunUsesTheClassifier(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell-script stand-in for msfconsole")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\necho '[*] Running with safe checks enabled'\necho '[+] 127.0.0.1:2323 - The target appears to be vulnerable.'\n"
	if err := os.WriteFile(filepath.Join(dir, "msfconsole"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	res, err := (&Metasploit{}).Run(context.Background(), Job{Host: "127.0.0.1", Port: 2323, Options: map[string]string{"module": "auxiliary/scanner/telnet/telnet_version"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Validation == nil || res.Validation.Verdict != "vulnerable" || res.Validation.Module != "auxiliary/scanner/telnet/telnet_version" {
		t.Fatalf("validation = %+v", res.Validation)
	}
}

func TestMetasploitRunNeverReportsSafeFromTheSubstring(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell-script stand-in for msfconsole")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\necho '[*] safe checks only'\necho '[*] Cannot reliably check exploitability.'\n"
	if err := os.WriteFile(filepath.Join(dir, "msfconsole"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	res, err := (&Metasploit{}).Run(context.Background(), Job{Host: "127.0.0.1", Port: 2323, Options: map[string]string{"module": "auxiliary/scanner/telnet/telnet_version"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Validation == nil || res.Validation.Verdict != "undetermined" {
		t.Fatalf("validation = %+v, want undetermined", res.Validation)
	}
}
