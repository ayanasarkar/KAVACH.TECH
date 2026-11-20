package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func fixCode(h http.Handler, path string) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec.Code
}

func TestFixFlagHidesTheExposedFiles(t *testing.T) {
	flag := filepath.Join(t.TempDir(), "fixed.flag")
	t.Setenv("LAB_FIXED_FLAG", flag)
	h := weakSite()
	want := func(when string, exposed, page int) {
		t.Helper()
		for _, p := range []string{"/.env", "/.git/HEAD"} {
			if got := fixCode(h, p); got != exposed {
				t.Errorf("%s %s: status %d, want %d", when, p, got, exposed)
			}
		}
		if got := fixCode(h, "/"); got != page {
			t.Errorf("%s /: status %d, want %d", when, got, page)
		}
	}
	want("before the fix", 200, 200)
	if err := os.WriteFile(flag, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	want("after the fix", 404, 200)
	if err := os.Remove(flag); err != nil {
		t.Fatal(err)
	}
	want("after the fix is undone", 200, 200)
}
