package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAICompatSendsKeyAndParsesReply(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("authorization"), r.URL.Path
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"reply\":\"hi\"}"}}]}`))
	}))
	defer srv.Close()
	c := &OpenAICompat{BaseURL: srv.URL + "/v1/", Key: "k123", Model: "m"}
	out, err := c.Complete(context.Background(), "sys", "usr")
	if err != nil || out != `{"reply":"hi"}` {
		t.Fatal(out, err)
	}
	if gotAuth != "Bearer k123" || gotPath != "/v1/chat/completions" {
		t.Errorf("auth=%q path=%q", gotAuth, gotPath)
	}
}

func TestOpenAICompatSurfacesAPIErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "quota", 429) }))
	defer srv.Close()
	if _, err := (&OpenAICompat{BaseURL: srv.URL, Model: "m"}).Complete(context.Background(), "s", "u"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDataLeavesIsHonest(t *testing.T) {
	cases := []struct {
		c    Client
		want bool
	}{
		{None{}, false},
		{&Anthropic{}, true},
		{&Ollama{URL: "http://127.0.0.1:11434"}, false},
		{&Ollama{URL: "http://localhost:11434"}, false},
		{&Ollama{URL: "http://192.168.1.9:11434"}, true}, // another machine, even on a LAN
		{&OpenAICompat{BaseURL: "http://127.0.0.1:1234/v1"}, false},
		{&OpenAICompat{BaseURL: "https://api.groq.com/openai/v1"}, true},
	}
	for _, c := range cases {
		if got := DataLeaves(c.c); got != c.want {
			t.Errorf("%s: got %v want %v", c.c.Name(), got, c.want)
		}
	}
}

func TestFromEnvPicksBackends(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("VAPT_OPENAI_URL", "")
	t.Setenv("OLLAMA_MODEL", "")
	if _, ok := FromEnv().(None); !ok {
		t.Error("want None")
	}
	t.Setenv("VAPT_OPENAI_URL", "http://127.0.0.1:1/v1")
	if _, ok := FromEnv().(None); !ok {
		t.Error("an OpenAI URL without VAPT_MODEL must not half-configure")
	}
	t.Setenv("VAPT_MODEL", "x")
	if _, ok := FromEnv().(*OpenAICompat); !ok {
		t.Error("want OpenAICompat")
	}
}
