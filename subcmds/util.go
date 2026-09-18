// Copyright (c) 2026 Visvasity LLC

// Package subcmds implements the hostcheck command-line subcommands on top of
// the github.com/visvasity/cli framework.
package subcmds

import (
	"strings"

	"github.com/visvasity/hostcheck/report"
)

// splitCSV splits a comma-separated flag value into trimmed, non-empty tokens.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// configFrom builds a report.Config from -enable/-disable flag values, starting
// from catalog defaults.
func configFrom(enable, disable string) report.Config {
	cfg := report.Config{}
	if keys := splitCSV(disable); len(keys) > 0 {
		cfg = cfg.Without(keys...)
	}
	if keys := splitCSV(enable); len(keys) > 0 {
		cfg = cfg.With(keys...)
	}
	return cfg
}
