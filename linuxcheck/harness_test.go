// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"context"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/visvasity/hostcheck/report"
	"github.com/visvasity/shcmd"
	"github.com/visvasity/unixcmds"
)

func runtimeRunner() unixcmds.Runner {
	return unixcmds.Runner{Runner: shcmd.Runtime()}
}

// sectionStatuses reflects over a Report and returns each Section field's status,
// keyed by Go field name. Non-section fields (the envelope, Platform) are skipped.
func sectionStatuses(rep *report.Report) map[string]report.Status {
	m := make(map[string]report.Status)
	v := reflect.ValueOf(*rep)
	t := v.Type()
	for i := range t.NumField() {
		f := v.Field(i)
		if f.Kind() != reflect.Struct {
			continue
		}
		if sf := f.FieldByName("Status"); sf.IsValid() && sf.Kind() == reflect.String {
			m[t.Field(i).Name] = report.Status(sf.String())
		}
	}
	return m
}

func TestCollectReportEnvelopeAndStatuses(t *testing.T) {
	reg := NewRegistry()
	Register(reg, fakeSSHD{section: Collected("sshd", report.SSHDConfig{PasswordAuthentication: true})}, sshdField)

	fixed := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	cfg := report.Config{}
	rep := CollectReport(context.Background(), reg, runtimeRunner(), cfg,
		Options{Now: func() time.Time { return fixed }})

	if rep.SchemaVersion != report.SchemaVersion {
		t.Errorf("SchemaVersion = %q", rep.SchemaVersion)
	}
	if !rep.GeneratedAt.Equal(fixed) {
		t.Errorf("GeneratedAt = %v, want %v", rep.GeneratedAt, fixed)
	}
	if rep.Mode != report.ModeLocal {
		t.Errorf("Mode = %q", rep.Mode)
	}
	if rep.Platform.OS != runtime.GOOS {
		t.Errorf("Platform.OS = %q, want %q", rep.Platform.OS, runtime.GOOS)
	}
	if rep.Platform.Arch == "" {
		t.Error("Platform.Arch empty")
	}
	if !reflect.DeepEqual(rep.EnabledModules, cfg.EnabledKeys()) {
		t.Errorf("EnabledModules = %v", rep.EnabledModules)
	}

	// Enabled + registered -> collected with data.
	if rep.SSHDConfig.Status != report.StatusCollected || rep.SSHDConfig.Data == nil {
		t.Errorf("SSHDConfig = %+v, want collected with data", rep.SSHDConfig)
	}
	// Disabled by default (package-inventory) -> disabled.
	if rep.PackageInventory.Status != report.StatusDisabled {
		t.Errorf("PackageInventory = %v, want disabled", rep.PackageInventory.Status)
	}
	// Enabled by default but no collector registered -> unsupported.
	if rep.ListeningTCP.Status != report.StatusUnsupported {
		t.Errorf("ListeningTCP = %v, want unsupported", rep.ListeningTCP.Status)
	}
}

// TestApplyStatusCoversCatalog guards against applyStatus drifting out of sync
// with the Report struct: with no collectors registered, every catalog module
// must receive a non-empty status (disabled or unsupported).
func TestApplyStatusCoversCatalog(t *testing.T) {
	rep := CollectReport(context.Background(), NewRegistry(), runtimeRunner(), report.Config{}, Options{})

	statuses := sectionStatuses(rep)
	if len(statuses) != len(report.Catalog) {
		t.Fatalf("found %d section fields, catalog has %d", len(statuses), len(report.Catalog))
	}
	for field, st := range statuses {
		if st == "" {
			t.Errorf("section %s has empty status (applyStatus missing a case)", field)
		}
	}
}
