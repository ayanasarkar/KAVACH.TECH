package pdf

import "testing"

// TestEscHandlesModelHyphens reproduces the exact garbling seen in a real report: the
// model (Groq's openai/gpt-oss-120b) wrote U+2011 NON-BREAKING HYPHEN in compound
// words such as "web‑server" and "Content‑Security‑Policy". That code point is outside
// WinAnsi/cp1252, so esc() fell through to a literal '?', rendering as "web?server" in
// the PDF. It and its close relatives (U+2010 HYPHEN, U+2012 FIGURE DASH) must render
// as a plain ASCII hyphen instead.
func TestEscHandlesModelHyphens(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"non-breaking hyphen (the observed bug)", "web‑server", "web-server"},
		{"plain unicode hyphen", "web‐server", "web-server"},
		{"figure dash", "web‒server", "web-server"},
		{"already-fine ASCII hyphen", "web-server", "web-server"},
		{"multiple in one string", "Content‑Security‑Policy", "Content-Security-Policy"},
		{"en dash still maps to its WinAnsi octal, not ASCII", "A–B", "A\\226B"},
		{"a genuinely unrepresentable char still falls back to '?'", "中", "?"},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			if got := esc(c.in); got != c.want {
				t.Errorf("esc(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
