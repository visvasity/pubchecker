// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"reflect"
	"testing"

	"github.com/visvasity/hostcheck/report"
)

// `ss -Hltnp` style output: v4+v6 wildcard sshd (should collapse to one),
// a loopback service, a routable service, and a socket with no process column
// (as seen when not running as root).
const ssListenOutput = `LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=800,fd=3))
LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=800,fd=4))
LISTEN 0 100 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=900,fd=5))
LISTEN 0 128 203.0.113.9:9100 0.0.0.0:* users:(("node_exporter",pid=1000,fd=6))
LISTEN 0 128 0.0.0.0:111 0.0.0.0:*
`

func TestParseListening(t *testing.T) {
	got := parseListening(ssListenOutput, "tcp")
	want := []report.ListeningSocket{
		{Protocol: "tcp", BindClass: "wildcard", Port: 22, Program: "sshd"},
		{Protocol: "tcp", BindClass: "wildcard", Port: 111, Program: ""},
		{Protocol: "tcp", BindClass: "loopback", Port: 5432, Program: "postgres"},
		{Protocol: "tcp", BindClass: "routable", Port: 9100, Program: "node_exporter"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseListening mismatch:\n got: %+v\nwant: %+v", got, want)
	}
}

func TestSplitLocal(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		ok   bool
	}{
		{"0.0.0.0:22", "0.0.0.0", 22, true},
		{"[::]:22", "::", 22, true},
		{"[::1]:5432", "::1", 5432, true},
		{"127.0.0.1:5432", "127.0.0.1", 5432, true},
		{"*:111", "*", 111, true},
		{"garbage", "", 0, false},
		{"0.0.0.0:*", "", 0, false}, // non-numeric port
	}
	for _, c := range cases {
		host, port, ok := splitLocal(c.in)
		if ok != c.ok || (ok && (host != c.host || port != c.port)) {
			t.Errorf("splitLocal(%q) = %q,%d,%v; want %q,%d,%v", c.in, host, port, ok, c.host, c.port, c.ok)
		}
	}
}

func TestBindClassForHost(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0":      "wildcard",
		"::":           "wildcard",
		"*":            "wildcard",
		"":             "wildcard",
		"127.0.0.1":    "loopback",
		"::1":          "loopback",
		"203.0.113.4":  "routable",
		"fe80::1%eth0": "routable",
	}
	for host, want := range cases {
		if got := bindClassForHost(host); got != want {
			t.Errorf("bindClassForHost(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestSSProgram(t *testing.T) {
	fields := []string{"LISTEN", "0", "128", "0.0.0.0:22", "0.0.0.0:*", `users:(("sshd",pid=800,fd=3))`}
	if got := ssProgram(fields); got != "sshd" {
		t.Errorf("ssProgram = %q, want sshd", got)
	}
	if got := ssProgram([]string{"LISTEN", "0", "128", "0.0.0.0:111", "0.0.0.0:*"}); got != "" {
		t.Errorf("ssProgram (no process column) = %q, want empty", got)
	}
}
