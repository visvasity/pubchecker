// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"reflect"
	"testing"

	"github.com/visvasity/hostcheck/report"
)

// A representative `sshd -T` excerpt: hardened defaults with a couple of
// deliberately weak/notable directives to exercise the parser.
const sshdTOutput = `port 22
port 2222
addressfamily any
listenaddress 0.0.0.0:22
listenaddress [::]:22
listenaddress 127.0.0.1:22
permitrootlogin without-password
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
permitemptypasswords no
x11forwarding no
allowtcpforwarding yes
maxauthtries 4
allowgroups sshusers admins
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
macs hmac-sha2-256-etm@openssh.com,hmac-sha1
kexalgorithms curve25519-sha256,diffie-hellman-group1-sha1
`

func TestParseSSHDConfig(t *testing.T) {
	got := parseSSHDConfig(sshdTOutput)
	want := report.SSHDConfig{
		Port:                         []int{22, 2222},
		ListenAddressClass:           []string{"loopback", "wildcard"},
		PermitRootLogin:              "without-password",
		PasswordAuthentication:       false,
		KbdInteractiveAuthentication: false,
		PubkeyAuthentication:         true,
		PermitEmptyPasswords:         false,
		X11Forwarding:                false,
		AllowTCPForwarding:           "yes",
		MaxAuthTries:                 4,
		HasAllowUsers:                false,
		HasAllowGroups:               true,
		CipherStrengthSummary:        "strong",
		MACStrengthSummary:           "weak", // hmac-sha1 present
		KexStrengthSummary:           "weak", // diffie-hellman-group1-sha1 present
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseSSHDConfig mismatch:\n got: %+v\nwant: %+v", got, want)
	}
}

func TestListenAddrClass(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0:22":     "wildcard",
		"[::]:22":        "wildcard",
		":22":            "wildcard",
		"127.0.0.1:22":   "loopback",
		"[::1]:22":       "loopback",
		"203.0.113.4:22": "routable",
		"garbage":        "routable",
	}
	for in, want := range cases {
		if got := listenAddrClass(in); got != want {
			t.Errorf("listenAddrClass(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAlgoStrength(t *testing.T) {
	if algoStrength("chacha20-poly1305@openssh.com,aes256-gcm@openssh.com") != "strong" {
		t.Error("modern ciphers should be strong")
	}
	if algoStrength("aes128-cbc,aes256-ctr") != "weak" {
		t.Error("cbc should be weak")
	}
	if algoStrength("diffie-hellman-group1-sha1") != "weak" {
		t.Error("group1-sha1 should be weak")
	}
}

func TestSSHDInDefaultRegistry(t *testing.T) {
	reg := DefaultRegistry()
	if !reg.Has(report.KeySSHDConfig) {
		t.Fatal("sshd-config not registered in DefaultRegistry")
	}
	cmds, ok := reg.Commands(report.KeySSHDConfig)
	if !ok || len(cmds) != 1 || cmds[0].Argv[0] != "sshd" {
		t.Errorf("unexpected commands: %+v (ok=%v)", cmds, ok)
	}
}
