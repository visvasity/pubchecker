// Copyright (c) 2026 Visvasity LLC

package subcmds

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestFormatVersion(t *testing.T) {
	bi := &debug.BuildInfo{
		GoVersion: "go1.26.0",
		Main:      debug.Module{Version: "v1.2.3"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abcdef1234567890deadbeef"},
			{Key: "vcs.time", Value: "2026-09-18T00:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	got := formatVersion(bi)
	for _, want := range []string{"v1.2.3", "abcdef123456", "-dirty", "2026-09-18T00:00:00Z", "go1.26.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("formatVersion = %q, missing %q", got, want)
		}
	}
	// Revision is truncated to 12 chars.
	if strings.Contains(got, "abcdef1234567890") {
		t.Errorf("revision not truncated: %q", got)
	}
}

func TestFormatVersionDevel(t *testing.T) {
	// A local build with no VCS info: version present, no revision parens.
	bi := &debug.BuildInfo{GoVersion: "go1.26.0", Main: debug.Module{Version: "(devel)"}}
	got := formatVersion(bi)
	if !strings.Contains(got, "(devel)") || !strings.Contains(got, "go1.26.0") {
		t.Errorf("formatVersion = %q", got)
	}
	if strings.Contains(got, "-dirty") {
		t.Errorf("unexpected dirty marker: %q", got)
	}
}

func TestFormatVersionEmptyMain(t *testing.T) {
	bi := &debug.BuildInfo{GoVersion: "go1.26.0"}
	if got := formatVersion(bi); !strings.Contains(got, "(unknown)") {
		t.Errorf("empty main version should render (unknown): %q", got)
	}
}
