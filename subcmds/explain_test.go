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
	mods := buildExplain(reg, report.Config{})

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
	if m, _ := find(buildExplain(reg, cfg), report.KeySSHDConfig); m.State != stateDisabled {
		t.Errorf("disabled sshd-config state = %q, want %q", m.State, stateDisabled)
	}
	// Commands still shown for a registered-but-disabled module (transparency).
	if m, _ := find(buildExplain(reg, cfg), report.KeySSHDConfig); len(m.Commands) == 0 {
		t.Error("commands should be listed for a registered module even when disabled")
	}
}
