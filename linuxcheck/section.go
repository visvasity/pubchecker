// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"fmt"

	"github.com/visvasity/hostcheck/report"
)

// Section constructors keep collector code short and make the five resolution
// states explicit at every return site.

// Collected returns a successful section carrying data, tagged with the provider
// (the tool or source that supplied it, e.g. "ss", "iproute2", "sshd").
func Collected[T any](provider string, data T) report.Section[T] {
	return report.Section[T]{Status: report.StatusCollected, Provider: provider, Data: &data}
}

// Disabled returns a section marking the module turned off by configuration.
func Disabled[T any]() report.Section[T] {
	return report.Section[T]{Status: report.StatusDisabled}
}

// NotApplicable returns a section marking that no meaningful provider exists on
// this host (e.g. the underlying tool is not installed).
func NotApplicable[T any]() report.Section[T] {
	return report.Section[T]{Status: report.StatusNotApplicable}
}

// Unsupported returns a section marking that the fact exists on this platform but
// this build has no provider for it yet.
func Unsupported[T any]() report.Section[T] {
	return report.Section[T]{Status: report.StatusUnsupported}
}

// Errorf returns an error section with a formatted detail. Use it when
// collection was attempted but failed or was incomplete: the outcome is reduced
// confidence, never "no change".
func Errorf[T any](format string, args ...any) report.Section[T] {
	return report.Section[T]{Status: report.StatusError, Error: fmt.Sprintf(format, args...)}
}

// fail converts a command execution error into the appropriate non-collected
// section: not-applicable when the tool is absent, error otherwise (preserving
// the detail). It is the common tail of a collector that shells out.
func fail[T any](err error) report.Section[T] {
	if st := classify(err); st != report.StatusError {
		return report.Section[T]{Status: st}
	}
	return report.Section[T]{Status: report.StatusError, Error: err.Error()}
}
