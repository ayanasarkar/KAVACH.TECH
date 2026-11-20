package adapters

import "testing"

func TestAbsentHeaderChecksApply(t *testing.T) {
	cases := map[int]bool{
		200: true, 204: true, 299: true,
		0: false, 199: false, 301: false, 302: false, 308: false,
		401: false, 403: false, 404: false, 500: false, 503: false, 523: false,
	}
	for status, want := range cases {
		if got := absentHeaderChecksApply(status); got != want {
			t.Errorf("absentHeaderChecksApply(%d) = %v, want %v", status, got, want)
		}
	}
}
