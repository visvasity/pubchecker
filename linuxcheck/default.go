// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import "github.com/visvasity/hostcheck/report"

// DefaultRegistry returns a registry with every collector implemented by this
// build registered. It is the agent's capability set; modules not registered
// here resolve to StatusUnsupported when enabled. Collectors are added to
// registerDefaults as they are implemented.
func DefaultRegistry() *Registry {
	reg := NewRegistry()
	registerDefaults(reg)
	return reg
}

func registerDefaults(reg *Registry) {
	Register(reg, SSHD(), func(r *report.Report) *report.Section[report.SSHDConfig] { return &r.SSHDConfig })
}
