package adapters

import (
	"context"
	"testing"
)

func TestValidModule(t *testing.T) {
	for _, m := range []string{"auxiliary/scanner/telnet/telnet_version", "auxiliary/scanner/http/http_version", "exploit/unix/ftp/vsftpd_234_backdoor"} {
		if err := ValidModule(m); err != nil {
			t.Errorf("%q should be accepted: %v", m, err)
		}
	}
	for _, m := range []string{"", "   ", "auxiliary", "auxiliary/admin/smb/x", "auxiliary/scanner/../x", "use x; exit", "Auxiliary/Scanner/x"} {
		if err := ValidModule(m); err == nil {
			t.Errorf("%q should be rejected", m)
		}
	}
}

func TestMetasploitWithoutMsfconsoleIsUndetermined(t *testing.T) {
	if ok, _ := have("msfconsole"); ok {
		t.Skip("msfconsole is installed, so the fallback is not used")
	}
	res, err := (&Metasploit{}).Run(context.Background(), Job{Host: "127.0.0.1", Port: 2323, Options: map[string]string{"module": "auxiliary/scanner/telnet/telnet_version"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Validation == nil || res.Validation.Verdict != "undetermined" {
		t.Fatalf("verdict = %+v, want undetermined", res.Validation)
	}
}
