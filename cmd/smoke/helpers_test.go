package main

import (
	"reflect"
	"testing"
)

// windowsLabLog is the lab's output from a real Windows run where the OS reserved most of the lab's ports.
const windowsLabLog = `2026/11/19 02:09:41 lab weak-web   port 8081 unavailable (listen tcp 127.0.0.1:8081: listen: An attempt was made to access a socket in a way forbidden by its access permissions.), trying next
2026/11/19 02:09:41 lab weak-web   on 127.0.0.1:8088
2026/11/19 02:09:41 lab spa-web    port 8000 unavailable (listen tcp 127.0.0.1:8000: listen: An attempt was made to access a socket in a way forbidden by its access permissions.), trying next
2026/11/19 02:09:41 lab spa-web    on 127.0.0.1:5000
2026/11/19 02:09:41 lab inject-web port 8080 unavailable (listen tcp 127.0.0.1:8080: listen: An attempt was made to access a socket in a way forbidden by its access permissions.), trying next
2026/11/19 02:09:41 lab inject-web could not bind any of [8080 8009]: skipped
2026/11/19 02:09:41 lab ftp        port 2121 unavailable (listen tcp 127.0.0.1:2121: listen: An attempt was made to access a socket in a way forbidden by its access permissions.), trying next
2026/11/19 02:09:41 lab ftp        could not bind any of [2121 2222]: skipped
2026/11/19 02:09:41 lab telnet     port 2323 unavailable (listen tcp 127.0.0.1:2323: listen: An attempt was made to access a socket in a way forbidden by its access permissions.), trying next
2026/11/19 02:09:41 lab telnet     could not bind any of [2323 23]: skipped
2026/11/19 02:09:41 lab inject-mx  could not bind any of [2525 587]: skipped
`

func TestSkippedServices(t *testing.T) {
	got := skippedServices(windowsLabLog)
	want := []string{"inject-web", "ftp", "telnet", "inject-mx"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skippedServices = %v, want %v", got, want)
	}
	healthy := "2026/11/19 02:09:41 lab telnet     on 127.0.0.1:2323\n2026/11/19 02:09:41 lab ftp        on 127.0.0.1:2121\n"
	if got := skippedServices(healthy); len(got) != 0 {
		t.Fatalf("a healthy lab reported skipped services: %v", got)
	}
}

func TestLabTelnetSettled(t *testing.T) {
	cases := []struct {
		name string
		log  string
		want bool
	}{
		{"telnet given up", windowsLabLog, true},
		{"telnet bound", "lab telnet     on 127.0.0.1:2323\n", true},
		{"telnet bound on the fallback port", "lab telnet     port 2323 unavailable (listen tcp 127.0.0.1:2323: in use), trying next\nlab telnet     on 127.0.0.1:23\n", true},
		{"still starting", "lab weak-web   on 127.0.0.1:8081\nlab telnet     port 2323 unavailable (listen tcp 127.0.0.1:2323: in use), trying next\n", false},
		{"nothing yet", "", false},
	}
	for _, c := range cases {
		if got := labTelnetSettled(c.log); got != c.want {
			t.Errorf("%s: labTelnetSettled = %v, want %v", c.name, got, c.want)
		}
	}
}
