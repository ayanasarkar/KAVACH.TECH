package report

import (
	"strings"
	"testing"
)

func TestAddressingLine(t *testing.T) {
	if got := addressingLine(false, nil); !strings.Contains(got, "lab-only enforced") {
		t.Errorf("default: %s", got)
	}
	got := addressingLine(false, []string{"www.hackthecore.in"})
	if !strings.Contains(got, "www.hackthecore.in") || !strings.Contains(got, "public addresses") || strings.Contains(got, "lab-only enforced") {
		t.Errorf("authorised domain must be disclosed, not reported as plain lab-only: %s", got)
	}
	if got := addressingLine(true, nil); !strings.Contains(got, "organiser override") {
		t.Errorf("override: %s", got)
	}
}
