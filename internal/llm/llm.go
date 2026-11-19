// Package llm provides swappable model back-ends. The agent treats model output
// as untrusted proposals: it is parsed as strict JSON, validated, and every
// proposed action is re-checked by the scope guard before anything runs.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrNoModel means no LLM is configured; the agent falls back to its rules planner.
var ErrNoModel = errors.New("no LLM configured")

// Client is a minimal chat-completion interface.
type Client interface {
	Name() string
	Complete(ctx context.Context, system, user string) (string, error)
}

// FromEnv picks a back-end: ANTHROPIC_API_KEY -> Anthropic, VAPT_OPENAI_URL -> any OpenAI-compatible
// server (key in VAPT_OPENAI_KEY, may be empty for a local server), OLLAMA_MODEL -> Ollama, else none.
func FromEnv() Client {
	if k := os.Getenv("ANTHROPIC_API_KEY"); k != "" {
		m := os.Getenv("VAPT_MODEL")
		if m == "" {
			m = "claude-sonnet-5-5"
		}
		return &Anthropic{Key: k, Model: m, BaseURL: os.Getenv("VAPT_ANTHROPIC_URL")}
	}
	if u := os.Getenv("VAPT_OPENAI_URL"); u != "" {
		m := os.Getenv("VAPT_MODEL")
		if m == "" {
			return None{}
		}
		return &OpenAICompat{BaseURL: u, Key: os.Getenv("VAPT_OPENAI_KEY"), Model: m}
	}
	if m := os.Getenv("OLLAMA_MODEL"); m != "" {
		u := os.Getenv("OLLAMA_URL")
		if u == "" {
			u = "http://127.0.0.1:11434"
		}
		return &Ollama{URL: strings.TrimRight(u, "/"), Model: m}
	}
	return None{}
}

// None is the rules-only mode.
type None struct{}

func (None) Name() string { return "rules-only (no LLM configured)" }
func (None) Complete(context.Context, string, string) (string, error) {
	return "", ErrNoModel
}

// Anthropic calls the Messages API. BaseURL is optional: empty means https://api.anthropic.com. It exists so the client
// can be tested against a local server or pointed at a gateway; set it with VAPT_ANTHROPIC_URL.
type Anthropic struct{ Key, Model, BaseURL string }

func (a *Anthropic) Name() string { return "anthropic:" + a.Model }

func (a *Anthropic) endpoint() string {
	b := strings.TrimRight(a.BaseURL, "/")
	if b == "" {
		b = "https://api.anthropic.com"
	}
	return b + "/v1/messages"
}

func (a *Anthropic) Complete(ctx context.Context, system, user string) (string, error) {
	// No temperature, top_p or top_k: Claude Sonnet 5.5 rejects non-default sampling parameters with a 400, and every
	// output here is validated by code anyway. max_tokens is generous because adaptive thinking is on by default on
	// these models and shares the budget with the visible answer.
	body, _ := json.Marshal(map[string]any{"model": a.Model, "max_tokens": 8192, "system": system,
		"messages": []map[string]string{{"role": "user", "content": user}}})
	req, err := http.NewRequestWithContext(ctx, "POST", a.endpoint(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", a.Key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("anthropic API %d: %.200s", resp.StatusCode, b)
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("unexpected anthropic response: %w", err)
	}
	// The reply is a list of blocks. With thinking on, a thinking block can come first, so join every text block
	// rather than assuming the first block is the answer.
	var text strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}
	if strings.TrimSpace(text.String()) == "" {
		return "", fmt.Errorf("anthropic returned no text (stop_reason %q)", out.StopReason)
	}
	return text.String(), nil
}

// Ollama calls a local model.
type Ollama struct{ URL, Model string }

func (o *Ollama) Name() string { return "ollama:" + o.Model }
func (o *Ollama) Complete(ctx context.Context, system, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{"model": o.Model, "stream": false, "format": "json", "options": map[string]any{"temperature": 0},
		"messages": []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}}})
	req, _ := http.NewRequestWithContext(ctx, "POST", o.URL+"/api/chat", bytes.NewReader(body))
	req.Header.Set("content-type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("ollama %d: %.200s", resp.StatusCode, b)
	}
	var out struct {
		Message struct{ Content string } `json:"message"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", err
	}
	return out.Message.Content, nil
}

// ExtractJSON pulls the first top-level JSON object out of a model reply.
func ExtractJSON(s string) (string, error) {
	i := strings.Index(s, "{")
	if i < 0 {
		return "", errors.New("no JSON object in model reply")
	}
	depth, inStr, esc := 0, false, false
	for j := i; j < len(s); j++ {
		c := s[j]
		switch {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[i : j+1], nil
			}
		}
	}
	return "", errors.New("unterminated JSON in model reply")
}
