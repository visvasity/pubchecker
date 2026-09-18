// Copyright (c) 2026 Visvasity LLC

package report

import (
	"slices"
	"testing"
)

func TestCatalogIntegrity(t *testing.T) {
	if got, want := len(Catalog), 36; got != want {
		t.Errorf("catalog has %d modules, want %d", got, want)
	}
	seen := make(map[string]bool)
	for _, d := range Catalog {
		if d.Key == "" {
			t.Error("descriptor with empty key")
		}
		if seen[d.Key] {
			t.Errorf("duplicate key %q", d.Key)
		}
		seen[d.Key] = true
	}
}

func TestGatewayEssentialSet(t *testing.T) {
	want := []string{KeyAgent, KeyHostIdentity, KeyPublicIP, KeyListeningTCP, KeyListeningUDP}
	got := GatewayEssentialKeys()
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("gateway-essential = %v, want %v", got, want)
	}
	// Every gateway-essential module must be enabled by default, or the default
	// config could not upload to the gateway.
	for _, key := range want {
		d, _ := Lookup(key)
		if !d.DefaultEnabled {
			t.Errorf("gateway-essential module %q is not enabled by default", key)
		}
	}
}

func TestDefaultConfigValidatesForGateway(t *testing.T) {
	if err := (Config{}).ValidateForGateway(); err != nil {
		t.Errorf("default config should satisfy the gateway: %v", err)
	}
}

func TestConfigResolution(t *testing.T) {
	// Default: catalog defaults apply.
	def := Config{}
	if !def.Enabled(KeyListeningTCP) {
		t.Error("listening-tcp should be on by default")
	}
	if def.Enabled(KeyPackageInventory) {
		t.Error("package-inventory should be off by default")
	}
	if def.Enabled("no-such-module") {
		t.Error("unknown key should never be enabled")
	}

	// Explicit override enables an off-by-default module and disables an on one.
	c := Config{}.With(KeyPackageInventory).Without(KeyListeningTCP)
	if !c.Enabled(KeyPackageInventory) {
		t.Error("explicit With should enable package-inventory")
	}
	if c.Enabled(KeyListeningTCP) {
		t.Error("explicit Without should disable listening-tcp")
	}

	// Disabling a gateway-essential module fails validation.
	if err := c.ValidateForGateway(); err == nil {
		t.Error("disabling listening-tcp should fail gateway validation")
	}

	// Disabling an identity-critical module is reported.
	ic := Config{}.Without(KeyPublicIP)
	if got := ic.DisabledIdentityCritical(); !slices.Contains(got, KeyPublicIP) {
		t.Errorf("DisabledIdentityCritical = %v, want it to contain %q", got, KeyPublicIP)
	}
}

func TestConfigSensitivityCap(t *testing.T) {
	// Cap at Low: high/moderate default-on modules drop out.
	c := Config{}.CapSensitivity(SensitivityLow)
	if c.Enabled(KeyAccounts) { // High
		t.Error("accounts (high) should be dropped by a low cap")
	}
	if c.Enabled(KeySSHAuthorizedKeys) { // Moderate
		t.Error("ssh-authorized-keys (moderate) should be dropped by a low cap")
	}
	if !c.Enabled(KeySSHDConfig) { // Low
		t.Error("sshd-config (low) should survive a low cap")
	}

	// Explicit opt-in wins over the cap.
	c2 := c.With(KeyAccounts)
	if !c2.Enabled(KeyAccounts) {
		t.Error("explicit With should override the sensitivity cap")
	}

	// A low cap drops gateway-essential modules above Low (public-ip is high;
	// host-identity and the listeners are moderate), so the gateway is no longer
	// satisfiable unless they are explicitly re-enabled.
	if err := c.ValidateForGateway(); err == nil {
		t.Error("a low cap should fail gateway validation")
	}
	if err := c.With(GatewayEssentialKeys()...).ValidateForGateway(); err != nil {
		t.Errorf("re-enabling the essential set should satisfy the gateway: %v", err)
	}
}
