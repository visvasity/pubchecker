// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"context"
	"testing"

	"github.com/visvasity/hostcheck/report"
	"github.com/visvasity/shcmd"
	"github.com/visvasity/unixcmds"
)

func testEnv() *Env {
	return &Env{Runner: unixcmds.Runner{Runner: shcmd.Runtime()}}
}

func TestClassifyFromRealCommands(t *testing.T) {
	ctx := context.Background()
	env := testEnv()

	// Missing binary (local runner) -> not-applicable.
	if _, err := output(ctx, env, "hostcheck-no-such-binary-xyz"); classify(err) != report.StatusNotApplicable {
		t.Errorf("missing binary: classify = %v, want not_applicable (err=%v)", classify(err), err)
	}
	// Shell exit 127 (command not found) -> not-applicable.
	if _, err := sh(ctx, env, "exit 127"); classify(err) != report.StatusNotApplicable {
		t.Errorf("exit 127: classify = %v, want not_applicable", classify(err))
	}
	// Ordinary non-zero exit -> error.
	if _, err := sh(ctx, env, "exit 3"); classify(err) != report.StatusError {
		t.Errorf("exit 3: classify = %v, want error", classify(err))
	}
	// Success -> collected (nil error).
	if _, err := sh(ctx, env, "true"); err != nil {
		t.Errorf("true: unexpected error %v", err)
	}
}

func TestOutputCapturesStdout(t *testing.T) {
	out, err := output(context.Background(), testEnv(), "echo", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if out != "hello\n" {
		t.Errorf("output = %q, want %q", out, "hello\n")
	}
}

func TestFailBuildsSections(t *testing.T) {
	ctx := context.Background()
	env := testEnv()

	_, err := output(ctx, env, "hostcheck-no-such-binary-xyz")
	if s := fail[report.SSHDConfig](err); s.Status != report.StatusNotApplicable || s.Data != nil {
		t.Errorf("missing tool: %+v, want not_applicable/no-data", s)
	}
	_, err = sh(ctx, env, "exit 3")
	if s := fail[report.SSHDConfig](err); s.Status != report.StatusError || s.Error == "" {
		t.Errorf("error path: %+v, want error status with detail", s)
	}
}

func TestRedactorHash(t *testing.T) {
	r := NewRedactor([]byte("host-salt"))
	if got := r.Hash(""); got != "" {
		t.Errorf("empty hash = %q, want empty", got)
	}
	a, b := r.Hash("alice"), r.Hash("alice")
	if a != b {
		t.Error("hash not stable for same input")
	}
	if r.Hash("bob") == a {
		t.Error("distinct inputs collided")
	}
	if NewRedactor([]byte("other-salt")).Hash("alice") == a {
		t.Error("different salt produced same digest")
	}
}

func TestPrefixIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":          "203.0.113.0/24",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1::/48",
	}
	for in, want := range cases {
		got, ok := PrefixIP(in)
		if !ok || got != want {
			t.Errorf("PrefixIP(%q) = %q,%v; want %q", in, got, ok, want)
		}
	}
	if _, ok := PrefixIP("not-an-ip"); ok {
		t.Error("PrefixIP accepted a non-address")
	}
}
