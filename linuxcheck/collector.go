// Copyright (c) 2026 Visvasity LLC

// Package linuxcheck implements the Linux collectors that populate a
// report.Report for the local host-check agent. Each collector observes one
// section of host state through a command runner, so the same code runs locally,
// over SSH, or through sudo by swapping the runner.
package linuxcheck

import (
	"context"

	"github.com/visvasity/hostcheck/report"
	"github.com/visvasity/unixcmds"
)

// Command is the declarative description of one external command a collector may
// execute. It exists for transparency: because the agent runs as root, it must
// be able to enumerate every command it would run (an --explain view). Commands
// are informational only and are never individually controllable — the module
// (section) is the sole unit of enable/disable.
type Command struct {
	// Argv is the command and its arguments. A shell pipeline is expressed in
	// the form {"sh", "-c", "<script>"}.
	Argv []string
	// Purpose is a one-line description of what this command contributes.
	Purpose string
	// NeedsRoot reports whether the command typically requires root privileges.
	NeedsRoot bool
}

// Env is the collection environment handed to every collector. It intentionally
// starts small and grows as shared helpers (clock, etc.) are added; collectors
// take what they need from it rather than reaching for global state.
type Env struct {
	// Runner executes commands and file operations on the target host.
	Runner unixcmds.Runner
	// Redact applies the shared redaction policy (salted hashing, IP prefixing).
	// The harness sets it; collectors that emit sensitive values MUST use it
	// rather than redacting ad hoc.
	Redact *Redactor
	// EnabledModules is the effective set of enabled module keys for this run,
	// in catalog order. The agent module hashes it into its config fingerprint.
	EnabledModules []string
}

// Collector collects exactly one report section, whose payload is of type T. A
// collector only observes; it never mutates host state.
//
// Collect deliberately returns no error: every outcome is expressed through the
// returned Section's Status (collected, not-applicable, unsupported, or error).
// This guarantees that a failure in one collector neither aborts the whole
// report nor is mistaken for "no change" — a failed collector reports its status
// and the rest proceed.
type Collector[T any] interface {
	// Key is the module's stable key (a report.Key* constant).
	Key() string
	// Commands returns the commands this collector may execute, for the
	// transparency/--explain view. It MUST be static: no host access, no
	// dependence on runtime state.
	Commands() []Command
	// Collect observes the host and returns the populated section.
	Collect(ctx context.Context, env *Env) report.Section[T]
}
