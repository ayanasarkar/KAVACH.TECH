package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The Anthropic client must never send sampling parameters (Claude Sonnet 5.5 answers them with a 400) and must
// cope with a reply whose first block is thinking rather than text.
func TestAnthropicRequestHasNoSamplingParameters(t *testing.T) {
	var sent map[string]any
	var gotKey, gotVersion, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotVersion, gotPath = r.Header.Get("x-api-key"), r.Header.Get("anthropic-version"), r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &sent)
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`))
	}))
	defer srv.Close()
	out, err := (&Anthropic{Key: "k1", Model: "claude-sonnet-5-5", BaseURL: srv.URL}).Complete(context.Background(), "sys", "usr")
	if err != nil || out != "ok" {
		t.Fatal(out, err)
	}
	for _, banned := range []string{"temperature", "top_p", "top_k"} {
		if _, present := sent[banned]; present {
			t.Errorf("request contains %q, which Claude Sonnet 5.5 rejects", banned)
		}
	}
	if gotKey != "k1" || gotVersion == "" || gotPath != "/v1/messages" {
		t.Errorf("key=%q version=%q path=%q", gotKey, gotVersion, gotPath)
	}
	if sent["model"] != "claude-sonnet-5-5" || sent["system"] != "sys" {
		t.Errorf("unexpected body: %v", sent)
	}
}

func TestAnthropicSkipsThinkingBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"content":[{"type":"thinking","thinking":"hmm","signature":"x"},{"type":"text","text":"{\"a\":"},{"type":"text","text":"1}"}],"stop_reason":"end_turn"}`))
	}))
	defer srv.Close()
	out, err := (&Anthropic{Key: "k", Model: "m", BaseURL: srv.URL}).Complete(context.Background(), "s", "u")
	if err != nil || out != `{"a":1}` {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestAnthropicErrorsAreSurfacedNotSwallowed(t *testing.T) {
	status := 400
	body := `{"type":"error","error":{"type":"invalid_request_error","message":"bad"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	c := &Anthropic{Key: "k", Model: "m", BaseURL: srv.URL}
	if _, err := c.Complete(context.Background(), "s", "u"); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("a 400 must surface as an error, got %v", err)
	}
	// A 200 with no text at all (for example thinking used the whole token budget) is an error, not an empty answer.
	status, body = 200, `{"content":[{"type":"thinking","thinking":"..."}],"stop_reason":"max_tokens"}`
	if _, err := c.Complete(context.Background(), "s", "u"); err == nil || !strings.Contains(err.Error(), "max_tokens") {
		t.Fatalf("an answer with no text must be an error naming the stop reason, got %v", err)
	}
}

func TestFromEnvHonoursAnthropicURLOverride(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "k")
	t.Setenv("VAPT_ANTHROPIC_URL", "http://127.0.0.1:9/")
	t.Setenv("VAPT_MODEL", "")
	a, ok := FromEnv().(*Anthropic)
	if !ok || a.BaseURL != "http://127.0.0.1:9/" || a.Model != "claude-sonnet-5-5" || a.endpoint() != "http://127.0.0.1:9/v1/messages" {
		t.Fatalf("got %+v", a)
	}
}
