// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/visvasity/hostcheck/report"
)

// SSHD returns the collector for the "sshd-config" module. It reads the
// effective SSH server configuration via `sshd -T`, the authoritative source
// (it resolves defaults, includes, and Match-independent globals), rather than
// parsing sshd_config files.
func SSHD() Collector[report.SSHDConfig] { return sshdCollector{} }

type sshdCollector struct{}

func (sshdCollector) Key() string { return report.KeySSHDConfig }

func (sshdCollector) Commands() []Command {
	return []Command{{
		Argv:      []string{"sshd", "-T"},
		Purpose:   "dump the effective sshd configuration",
		NeedsRoot: true,
	}}
}

func (sshdCollector) Collect(ctx context.Context, env *Env) report.Section[report.SSHDConfig] {
	// sshd usually lives in an sbin dir that may be off PATH; resolve it so a
	// thin PATH does not masquerade as "sshd absent".
	path, ok := lookTool(ctx, env, "sshd")
	if !ok {
		return NotApplicable[report.SSHDConfig]() // sshd is genuinely not installed
	}
	out, err := output(ctx, env, path, "-T")
	if err != nil {
		return fail[report.SSHDConfig](err) // present but failed (e.g. needs root)
	}
	return Collected("sshd", parseSSHDConfig(out))
}

// parseSSHDConfig parses `sshd -T` output. Each line is "keyword value..." with
// a lowercased keyword. Only exposure-relevant directives are extracted; the
// result is canonicalized (sorted ports and listen-address classes) so an
// unchanged server diffs equal.
func parseSSHDConfig(out string) report.SSHDConfig {
	var c report.SSHDConfig
	for _, line := range strings.Split(out, "\n") {
		key, val, _ := strings.Cut(strings.TrimSpace(line), " ")
		if key == "" {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.ToLower(key) {
		case "port":
			if n, err := strconv.Atoi(val); err == nil {
				c.Port = append(c.Port, n)
			}
		case "listenaddress":
			c.ListenAddressClass = append(c.ListenAddressClass, listenAddrClass(val))
		case "permitrootlogin":
			c.PermitRootLogin = val
		case "passwordauthentication":
			c.PasswordAuthentication = sshdYes(val)
		case "kbdinteractiveauthentication":
			c.KbdInteractiveAuthentication = sshdYes(val)
		case "pubkeyauthentication":
			c.PubkeyAuthentication = sshdYes(val)
		case "permitemptypasswords":
			c.PermitEmptyPasswords = sshdYes(val)
		case "x11forwarding":
			c.X11Forwarding = sshdYes(val)
		case "allowtcpforwarding":
			c.AllowTCPForwarding = val
		case "maxauthtries":
			if n, err := strconv.Atoi(val); err == nil {
				c.MaxAuthTries = n
			}
		case "allowusers":
			c.HasAllowUsers = true
		case "allowgroups":
			c.HasAllowGroups = true
		case "ciphers":
			c.CipherStrengthSummary = algoStrength(val)
		case "macs":
			c.MACStrengthSummary = algoStrength(val)
		case "kexalgorithms":
			c.KexStrengthSummary = algoStrength(val)
		}
	}
	c.Port = dedupSortedInts(c.Port)
	c.ListenAddressClass = dedupSorted(c.ListenAddressClass)
	return c
}

// sshdYes reports whether an sshd -T boolean value is "yes".
func sshdYes(val string) bool { return strings.EqualFold(val, "yes") }

// listenAddrClass reduces a ListenAddress value to its bind class. sshd -T emits
// addresses like "0.0.0.0:22" or "[::]:22"; the exact address is not retained.
func listenAddrClass(val string) string {
	host := strings.TrimSpace(val)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch host {
	case "0.0.0.0", "::", "*", "":
		return "wildcard"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "routable" // unknown form: assume reachable (conservative)
	}
	switch {
	case addr.IsUnspecified():
		return "wildcard"
	case addr.IsLoopback():
		return "loopback"
	default:
		return "routable"
	}
}

// weakAlgoSubstrings are lowercase markers of clearly-weak SSH algorithms. The
// list is deliberately conservative to avoid flagging modern defaults; it is a
// heuristic summary, not a policy engine (hard invariants live elsewhere).
var weakAlgoSubstrings = []string{
	"-cbc", "arcfour", "3des", "blowfish", "cast128",
	"hmac-md5", "hmac-sha1", "diffie-hellman-group1-sha1", "ssh-dss",
}

// algoStrength summarizes an algorithm list as "weak" if it contains any
// clearly-weak algorithm, else "strong".
func algoStrength(list string) string {
	l := strings.ToLower(list)
	for _, w := range weakAlgoSubstrings {
		if strings.Contains(l, w) {
			return "weak"
		}
	}
	return "strong"
}

func dedupSorted(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	slices.Sort(ss)
	return slices.Compact(ss)
}

func dedupSortedInts(ns []int) []int {
	if len(ns) == 0 {
		return nil
	}
	slices.Sort(ns)
	return slices.Compact(ns)
}
