package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OpenAICompat calls any server that speaks the OpenAI chat-completions dialect
// (OpenRouter, Groq, Together, LM Studio, vLLM, llama.cpp server, a hosted gateway...).
// Set VAPT_OPENAI_URL to the base (for example https://api.groq.com/openai/v1) and VAPT_MODEL.
type OpenAICompat struct{ BaseURL, Key, Model string }

func (o *OpenAICompat) Name() string { return "openai-compatible:" + o.Model }

func (o *OpenAICompat) Complete(ctx context.Context, system, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{"model": o.Model, "temperature": 0, "max_tokens": 4096,
		"messages": []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}}})
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(o.BaseURL, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	if o.Key != "" {
		req.Header.Set("authorization", "Bearer "+o.Key)
	}
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("openai-compatible API %d: %.200s", resp.StatusCode, b)
	}
	var out struct {
		Choices []struct {
			Message struct{ Content string } `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(b, &out); err != nil || len(out.Choices) == 0 {
		return "", fmt.Errorf("unexpected openai-compatible response")
	}
	return out.Choices[0].Message.Content, nil
}

// Remote reports whether prompts (and therefore scan data) are sent to a machine other than this one.
// It is an honest flag for the UI and the report: true for hosted APIs, false only for loopback/LAN-local servers.
type Remoter interface{ Remote() bool }

func (*Anthropic) Remote() bool { return true }
func (o *Ollama) Remote() bool  { return !isLoopback(o.URL) }
func (o *OpenAICompat) Remote() bool {
	return !isLoopback(o.BaseURL)
}
func (None) Remote() bool { return false }

// DataLeaves is true when the configured model is a remote service.
func DataLeaves(c Client) bool {
	if r, ok := c.(Remoter); ok {
		return r.Remote()
	}
	return true // unknown back-end: assume the worst
}

func isLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
