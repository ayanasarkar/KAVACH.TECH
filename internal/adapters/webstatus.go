package adapters

// absentHeaderChecksApply reports whether a missing security header on a response with this status says
// anything about the application. A redirect (3xx) or an error page (4xx/5xx, for example a CDN's
// "origin unreachable" 523) describes the redirect or the error page, not the application, so only a 2xx
// response can be judged for absent headers.
func absentHeaderChecksApply(status int) bool {
	return status >= 200 && status < 300
}
