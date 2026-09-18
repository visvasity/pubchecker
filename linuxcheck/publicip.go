// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"context"
	"net/netip"
	"strings"

	"github.com/visvasity/hostcheck/report"
)

// PublicIP returns the collector for the "public-ip" module. For this milestone
// it determines the host's public addresses locally from routable interface
// addresses (external echo/STUN is a later option). Addresses are prefix-redacted
// by default: exact addresses are never emitted without an explicit opt-in.
func PublicIP() Collector[report.PublicIP] { return publicIPCollector{} }

type publicIPCollector struct{}

func (publicIPCollector) Key() string { return report.KeyPublicIP }

func (publicIPCollector) Commands() []Command {
	return []Command{{
		Argv:    []string{"ip", "-o", "addr", "show", "scope", "global"},
		Purpose: "routable interface addresses",
	}}
}

func (publicIPCollector) Collect(ctx context.Context, env *Env) report.Section[report.PublicIP] {
	ipPath, ok := lookTool(ctx, env, "ip")
	if !ok {
		return NotApplicable[report.PublicIP]()
	}
	out, err := output(ctx, env, ipPath, "-o", "addr", "show", "scope", "global")
	if err != nil {
		return fail[report.PublicIP](err)
	}

	v4, v6 := parsePublicIPs(out)
	p := report.PublicIP{Source: "routing", Redacted: true}
	for _, a := range v4 {
		if pfx, ok := PrefixIP(a); ok {
			p.IPv4 = append(p.IPv4, pfx)
		}
	}
	for _, a := range v6 {
		if pfx, ok := PrefixIP(a); ok {
			p.IPv6 = append(p.IPv6, pfx)
		}
	}
	p.IPv4 = dedupSorted(p.IPv4)
	p.IPv6 = dedupSorted(p.IPv6)
	return Collected("iproute2", p)
}

// parsePublicIPs extracts the public (globally routable) IPv4 and IPv6 addresses
// from `ip -o addr` output, dropping private, loopback, link-local, and other
// non-public addresses. Returned addresses are bare (no prefix length).
func parsePublicIPs(out string) (v4, v6 []string) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] != "inet" && fields[i] != "inet6" {
				continue
			}
			addrStr, _, _ := strings.Cut(fields[i+1], "/")
			addr, err := netip.ParseAddr(addrStr)
			if err != nil || !isPublicAddr(addr) {
				continue
			}
			if addr.Is4() {
				v4 = append(v4, addrStr)
			} else {
				v6 = append(v6, addrStr)
			}
		}
	}
	return v4, v6
}

// isPublicAddr reports whether addr is a globally routable unicast address.
// netip.Addr.IsPrivate covers RFC 1918 and IPv6 ULA (fc00::/7).
func isPublicAddr(addr netip.Addr) bool {
	return addr.IsValid() &&
		!addr.IsUnspecified() &&
		!addr.IsLoopback() &&
		!addr.IsPrivate() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() &&
		!addr.IsMulticast()
}
