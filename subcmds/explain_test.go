// Copyright (c) 2026 Visvasity LLC

package subcmds

import (
	"testing"

	"github.com/visvasity/hostcheck/linuxcheck"
	"github.com/visvasity/hostcheck/report"
)

func find(mods []explainModule, key string) (explainModule, bool) {
	for _, m := range mods {
		if m.Key == key {
			return m, true
		}
	}
	return explainModule{}, false
}

func TestBuildExplain(t *testing.T) {
	reg := linuxcheck.DefaultRegistry()
	mods := buildExplain(reg, report.Config{}, nil)

	if len(mods) != len(report.Catalog) {
		t.Fatalf("explain has %d modules, catalog has %d", len(mods), len(report.Catalog))
	}

	// sshd-config: registered + enabled -> will_run, with its command shown.
	if m, ok := find(mods, report.KeySSHDConfig); !ok {
		t.Error("sshd-config missing")
	} else {
		if m.State != stateWillRun {
			t.Errorf("sshd-config state = %q, want %q", m.State, stateWillRun)
		}
		if len(m.Commands) != 1 || m.Commands[0].Argv[0] != "sshd" || !m.Commands[0].NeedsRoot {
			t.Errorf("sshd-config commands = %+v", m.Commands)
		}
	}

	// listening-tcp: enabled by default but no collector -> unsupported.
	if m, _ := find(mods, report.KeyListeningTCP); m.State != stateUnsupported {
		t.Errorf("listening-tcp state = %q, want %q", m.State, stateUnsupported)
	}

	// package-inventory: off by default -> disabled.
	if m, _ := find(mods, report.KeyPackageInventory); m.State != stateDisabled {
		t.Errorf("package-inventory state = %q, want %q", m.State, stateDisabled)
	}
}

func TestBuildExplainConfigOverrides(t *testing.T) {
	reg := linuxcheck.DefaultRegistry()

	cfg := report.Config{}.Without(report.KeySSHDConfig)
	if m, _ := find(buildExplain(reg, cfg, nil), report.KeySSHDConfig); m.State != stateDisabled {
		t.Errorf("disabled sshd-config state = %q, want %q", m.State, stateDisabled)
	}
	// Commands still shown for a registered-but-disabled module (transparency).
	if m, _ := find(buildExplain(reg, cfg, nil), report.KeySSHDConfig); len(m.Commands) == 0 {
		t.Error("commands should be listed for a registered module even when disabled")
	}
}

func TestBuildExplainCheck(t *testing.T) {
	reg := linuxcheck.DefaultRegistry()
	// Fake resolver: sshd is "not found", everything else resolves under /usr/bin.
	resolve := func(name string) (string, bool) {
		if name == "sshd" {
			return "", false
		}
		return "/usr/bin/" + name, true
	}

	m, ok := find(buildExplain(reg, report.Config{}, resolve), report.KeySSHDConfig)
	if !ok || len(m.Commands) != 1 {
		t.Fatalf("sshd-config command missing: %+v", m)
	}
	cmd := m.Commands[0]
	if cmd.Available == nil || *cmd.Available {
		t.Errorf("sshd should be reported unavailable, got %v", cmd.Available)
	}
	if cmd.ResolvedPath != "" {
		t.Errorf("unavailable command should have no resolved path, got %q", cmd.ResolvedPath)
	}
	if note := availabilityNote(cmd); note != "   [sshd: command not found]" {
		t.Errorf("availabilityNote = %q", note)
	}

	// Without a resolver, availability is left unset.
	m2, _ := find(buildExplain(reg, report.Config{}, nil), report.KeySSHDConfig)
	if m2.Commands[0].Available != nil {
		t.Error("availability should be nil when probing is disabled")
	}
}
