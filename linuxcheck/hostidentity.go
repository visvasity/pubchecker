// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/visvasity/hostcheck/report"
)

// HostIdentity returns the collector for the "host-identity" module: the facts
// that attribute a report to a host and surface reboots and kernel/patch drift.
func HostIdentity() Collector[report.HostIdentity] { return hostIdentityCollector{} }

type hostIdentityCollector struct{}

func (hostIdentityCollector) Key() string { return report.KeyHostIdentity }

func (hostIdentityCollector) Commands() []Command {
	return []Command{
		{Argv: []string{"hostname"}, Purpose: "host name"},
		{Argv: []string{"uname", "-s"}, Purpose: "operating system"},
		{Argv: []string{"uname", "-r"}, Purpose: "kernel version"},
	}
}

func (hostIdentityCollector) Collect(ctx context.Context, env *Env) report.Section[report.HostIdentity] {
	var h report.HostIdentity

	if name, err := env.Runner.Hostname(ctx); err == nil {
		h.Hostname = strings.TrimSpace(name)
	}
	h.MachineIDHash = machineIDHash(ctx, env)
	if s, err := output(ctx, env, "uname", "-s"); err == nil {
		h.OS = strings.ToLower(strings.TrimSpace(s))
	}
	if r, err := output(ctx, env, "uname", "-r"); err == nil {
		h.KernelVersion = strings.TrimSpace(r)
	}
	if data, err := env.Runner.ReadFile(ctx, "/etc/os-release"); err == nil {
		kv := parseOSRelease(string(data))
		h.Distribution = kv["ID"]
		h.Version = kv["VERSION_ID"]
	}
	if bt, ok := bootTime(ctx, env); ok {
		h.BootTime = bt
	}

	return Collected("uname", h)
}

// machineIDHash reads and salt-hashes the stable machine id. The raw id is never
// emitted. Returns "" if no machine-id source is readable.
func machineIDHash(ctx context.Context, env *Env) string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := env.Runner.ReadFile(ctx, path); err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return env.Redact.Hash(id)
			}
		}
	}
	return ""
}

// bootTime reads the absolute boot time from /proc/stat's btime line. Absolute
// boot time is a clean reboot signal (it changes only across reboots), unlike a
// constantly-ticking uptime.
func bootTime(ctx context.Context, env *Env) (time.Time, bool) {
	data, err := env.Runner.ReadFile(ctx, "/proc/stat")
	if err != nil {
		return time.Time{}, false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "btime ")
		if !ok {
			continue
		}
		if sec, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64); err == nil {
			return time.Unix(sec, 0).UTC(), true
		}
	}
	return time.Time{}, false
}
