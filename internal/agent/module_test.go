package agent

import (
	"strings"
	"testing"
)

func TestRequestValidationRefusesBlankModuleFirst(t *testing.T) {
	env := restoreEnv(t)
	a, err := New(env, "20261104-101010-abcd", "scan", restoreScope(), []string{"127.0.0.1"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, err = a.RequestValidation("F-001", "", "tester")
	if err == nil || !strings.Contains(err.Error(), "module") {
		t.Fatalf("want a module error, got %v", err)
	}
	if len(a.Steps) != 0 || len(a.Approvals) != 0 {
		t.Fatal("a blank module must not create a step or an approval")
	}
}
