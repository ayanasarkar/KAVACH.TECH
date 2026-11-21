package adapters

import "regexp"

// Secrets that appear in a tool's output must not be copied into the evidence excerpt, because the excerpt is what the
// PDF prints and what the model is shown. The raw output file on disk is left untouched, so its SHA-256 still matches
// what the tool produced; only the excerpt is redacted. Redaction is deliberately greedy: showing "<redacted>" where a
// harmless value stood is the safe way to be wrong.
var (
	// NAME=value / NAME: value where NAME mentions a secret-like word (DB_PASSWORD, API_KEY, AWS_SECRET_ACCESS_KEY ...).
	secretKV = regexp.MustCompile(`(?i)([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|credential)[A-Za-z0-9_.\-]*\s*[=:]\s*)[^\s;,&"'<]+`)
	// Cookie and Set-Cookie headers: keep the cookie name and attributes, drop the value.
	cookieKV = regexp.MustCompile(`(?i)((?:set-)?cookie\s*:\s*[^=\s;]+=)[^;\s]+`)
	// Authorization headers.
	authHdr = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*(?:bearer\s+|basic\s+)?)[^\s;,"']+`)
	// Well-known token shapes, wherever they appear.
	tokenShape = regexp.MustCompile(`\b(?:sk_(?:live|test)_|sk-|ghp_|gho_|github_pat_|xox[abp]-|AKIA|ASIA|AIza)[A-Za-z0-9_\-]{8,}`)
	// PEM private keys.
	pemKey = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`)
)

// RedactSecrets returns s with credential values replaced by <redacted>. It is idempotent.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	s = pemKey.ReplaceAllString(s, "<redacted private key>")
	s = cookieKV.ReplaceAllString(s, "${1}<redacted>")
	s = authHdr.ReplaceAllString(s, "${1}<redacted>")
	s = secretKV.ReplaceAllString(s, "${1}<redacted>")
	s = tokenShape.ReplaceAllString(s, "<redacted>")
	return s
}
