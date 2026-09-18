// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"context"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/visvasity/hostcheck/report"
)

func TestAgentCollect(t *testing.T) {
	env := testEnv()
	env.EnabledModules = []string{report.KeyAgent, report.KeySSHDConfig}

	sec := Agent().Collect(context.Background(), env)
	if sec.Status != report.StatusCollected || sec.Data == nil {
		t.Fatalf("agent section = %+v", sec)
	}
	a := sec.Data
	if a.OS != runtime.GOOS || a.Arch != runtime.GOARCH {
		t.Errorf("agent os/arch = %s/%s, want %s/%s", a.OS, a.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if a.Version == "" {
		t.Error("agent version empty")
	}
	if a.ConfigHash != configHash(env.EnabledModules) {
		t.Error("config hash mismatch")
	}
}

func TestConfigHashStableAndUnsalted(t *testing.T) {
	keys := []string{"agent", "sshd-config"}
	if configHash(keys) != configHash(slices.Clone(keys)) {
		t.Error("config hash not stable for equal input")
	}
	if configHash(keys) == configHash([]string{"agent"}) {
		t.Error("different configs should hash differently")
	}
}

func TestParsePublicIPs(t *testing.T) {
	// Mixed output: one public v4, one public v6, plus private/loopback/link-local
	// that must be excluded.
	out := `1: lo    inet 127.0.0.1/8 scope host lo
2: eth0    inet 10.0.0.5/24 scope global eth0
2: eth0    inet 203.0.113.7/24 brd 203.0.113.255 scope global eth0
2: eth0    inet6 fe80::1/64 scope link
2: eth0    inet6 2001:db8:abcd:1::5/64 scope global
2: eth0    inet6 fd00::1/64 scope global
`
	v4, v6 := parsePublicIPs(out)
	if !slices.Equal(v4, []string{"203.0.113.7"}) {
		t.Errorf("v4 = %v, want [203.0.113.7]", v4)
	}
	if !slices.Equal(v6, []string{"2001:db8:abcd:1::5"}) {
		t.Errorf("v6 = %v, want [2001:db8:abcd:1::5]", v6)
	}
}

func TestPublicIPCollectRedacts(t *testing.T) {
	// On this host there may be no public IP; regardless, the collector must
	// resolve `ip`, mark Redacted, and never emit an exact address.
	sec := PublicIP().Collect(context.Background(), testEnv())
	if sec.Status == report.StatusCollected {
		if !sec.Data.Redacted {
			t.Error("public-ip must be redacted by default")
		}
		if sec.Data.Source != "routing" {
			t.Errorf("source = %q, want routing", sec.Data.Source)
		}
		for _, a := range append(sec.Data.IPv4, sec.Data.IPv6...) {
			if !strings.Contains(a, "/") {
				t.Errorf("address %q is not a prefix (exact address leaked)", a)
			}
		}
	}
}

func TestHostIdentityCollect(t *testing.T) {
	sec := HostIdentity().Collect(context.Background(), testEnv())
	if sec.Status != report.StatusCollected || sec.Data == nil {
		t.Fatalf("host-identity section = %+v", sec)
	}
	h := sec.Data
	if h.OS != "linux" {
		t.Errorf("os = %q, want linux", h.OS)
	}
	if h.Hostname == "" {
		t.Error("hostname empty")
	}
	if h.KernelVersion == "" {
		t.Error("kernel version empty")
	}
	// machine-id / boot time exist on a normal Linux host; tolerate absence in
	// unusual sandboxes but log it.
	if h.MachineIDHash == "" {
		t.Log("machine-id not readable in this environment")
	}
	if h.BootTime.IsZero() {
		t.Log("/proc/stat btime not readable in this environment")
	}
}
