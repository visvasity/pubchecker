// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"context"
	"testing"

	"github.com/visvasity/hostcheck/report"
)

// fakeSSHD is a stand-in Collector used to exercise the contract without
// touching a host.
type fakeSSHD struct {
	section report.Section[report.SSHDConfig]
}

func (fakeSSHD) Key() string { return report.KeySSHDConfig }

func (fakeSSHD) Commands() []Command {
	return []Command{{Argv: []string{"sshd", "-T"}, Purpose: "effective sshd config"}}
}

func (f fakeSSHD) Collect(context.Context, *Env) report.Section[report.SSHDConfig] {
	return f.section
}

func sshdField(r *report.Report) *report.Section[report.SSHDConfig] { return &r.SSHDConfig }

func TestRegistryComposition(t *testing.T) {
	reg := NewRegistry()
	want := report.Section[report.SSHDConfig]{
		Status: report.StatusCollected,
		Data:   &report.SSHDConfig{PasswordAuthentication: true},
	}
	Register(reg, fakeSSHD{section: want}, sshdField)

	if !reg.Has(report.KeySSHDConfig) {
		t.Fatal("collector not registered")
	}
	if got := reg.Keys(); len(got) != 1 || got[0] != report.KeySSHDConfig {
		t.Fatalf("Keys() = %v", got)
	}
	if cmds, ok := reg.Commands(report.KeySSHDConfig); !ok || len(cmds) != 1 {
		t.Fatalf("Commands() = %v, %v", cmds, ok)
	}

	// A registered collector places its typed section into the right Report field.
	var rep report.Report
	reg.order[0].collect(context.Background(), &Env{}, &rep)
	if rep.SSHDConfig.Status != report.StatusCollected ||
		rep.SSHDConfig.Data == nil ||
		!rep.SSHDConfig.Data.PasswordAuthentication {
		t.Fatalf("collect did not populate SSHDConfig: %+v", rep.SSHDConfig)
	}

	// setStatus writes a data-less section (disabled/not-applicable path).
	reg.order[0].setStatus(&rep, report.StatusDisabled)
	if rep.SSHDConfig.Status != report.StatusDisabled || rep.SSHDConfig.Data != nil {
		t.Fatalf("setStatus did not reset SSHDConfig: %+v", rep.SSHDConfig)
	}
}

func TestRegisterRejectsUnknownKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic for unknown catalog key")
		}
	}()
	reg := NewRegistry()
	Register(reg, badKeyCollector{}, sshdField)
}

type badKeyCollector struct{}

func (badKeyCollector) Key() string      { return "not-a-real-module" }
func (badKeyCollector) Commands() []Command { return nil }
func (badKeyCollector) Collect(context.Context, *Env) report.Section[report.SSHDConfig] {
	return report.Section[report.SSHDConfig]{}
}
