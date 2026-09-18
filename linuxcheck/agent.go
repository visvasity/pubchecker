// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"runtime/debug"

	"github.com/visvasity/hostcheck/report"
)

// Agent returns the collector for the "agent" module. It describes the agent
// binary that produced the report (version, build, OS/arch) and a fingerprint of
// the effective configuration. It reports on the agent itself, so it runs no
// host commands and its OS/arch are the binary's, not the target's (the target
// platform is in the report envelope).
func Agent() Collector[report.Agent] { return agentCollector{} }

type agentCollector struct{}

func (agentCollector) Key() string { return report.KeyAgent }

func (agentCollector) Commands() []Command { return nil }

func (agentCollector) Collect(ctx context.Context, env *Env) report.Section[report.Agent] {
	a := report.Agent{
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		ConfigHash: configHash(env.EnabledModules),
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		a.Version = bi.Main.Version
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				a.Build = s.Value
				if len(a.Build) > 12 {
					a.Build = a.Build[:12]
				}
			}
		}
	}
	if a.Version == "" {
		a.Version = "(unknown)"
	}
	return Collected("buildinfo", a)
}

// configHash is an unsalted, stable digest of the enabled-module set. It is not
// a secret; it is a change marker, so it must be identical for identical configs
// across hosts (hence unsalted, unlike Redactor.Hash).
func configHash(keys []string) string {
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
