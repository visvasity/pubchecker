// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/visvasity/hostcheck/report"
)

// ListeningTCP and ListeningUDP return the collectors for the listening-socket
// modules. They enumerate listening sockets with `ss`, recording each socket's
// bind class (wildcard/routable/loopback), port, and owning program — the core
// open-port exposure signal. The exact bind address is not emitted; the bind
// class carries the security-relevant fact.
func ListeningTCP() Collector[report.ListeningSockets] {
	return listeningCollector{proto: "tcp", key: report.KeyListeningTCP, flag: "-t"}
}

func ListeningUDP() Collector[report.ListeningSockets] {
	return listeningCollector{proto: "udp", key: report.KeyListeningUDP, flag: "-u"}
}

type listeningCollector struct {
	proto string // "tcp" | "udp"
	key   string // module key
	flag  string // ss protocol flag ("-t" | "-u")
}

func (c listeningCollector) Key() string { return c.key }

func (c listeningCollector) Commands() []Command {
	return []Command{{
		Argv:    []string{"ss", "-H", "-l", "-n", "-p", c.flag},
		Purpose: "listening " + c.proto + " sockets (program names need root)",
	}}
}

func (c listeningCollector) Collect(ctx context.Context, env *Env) report.Section[report.ListeningSockets] {
	ssPath, ok := lookTool(ctx, env, "ss")
	if !ok {
		return NotApplicable[report.ListeningSockets]()
	}
	out, err := output(ctx, env, ssPath, "-H", "-l", "-n", "-p", c.flag)
	if err != nil {
		return fail[report.ListeningSockets](err)
	}
	return Collected("ss", report.ListeningSockets{Sockets: parseListening(out, c.proto)})
}

// parseListening parses `ss -H -l -n -p` output into canonical socket records:
// deduplicated (an IPv4 and IPv6 wildcard listener collapse to one) and sorted
// so an unchanged host diffs equal.
func parseListening(out, proto string) []report.ListeningSocket {
	var socks []report.ListeningSocket
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		// Columns: State Recv-Q Send-Q Local:Port Peer:Port [Process]
		if len(fields) < 4 {
			continue
		}
		host, port, ok := splitLocal(fields[3])
		if !ok {
			continue
		}
		socks = append(socks, report.ListeningSocket{
			Protocol:  proto,
			BindClass: bindClassForHost(host),
			Port:      port,
			Program:   ssProgram(fields),
		})
	}
	slices.SortFunc(socks, func(a, b report.ListeningSocket) int {
		if a.Port != b.Port {
			return cmp.Compare(a.Port, b.Port)
		}
		if a.BindClass != b.BindClass {
			return cmp.Compare(a.BindClass, b.BindClass)
		}
		return cmp.Compare(a.Program, b.Program)
	})
	return slices.Compact(socks) // ListeningSocket is comparable; drops adjacent dups
}

// splitLocal splits an ss "Local Address:Port" token into host and numeric port,
// handling bracketed IPv6 ("[::]:22") and bare host:port forms.
func splitLocal(s string) (host string, port int, ok bool) {
	if rest, found := strings.CutPrefix(s, "["); found {
		end := strings.LastIndex(rest, "]")
		if end < 0 {
			return "", 0, false
		}
		host = rest[:end]
		portStr, hasPort := strings.CutPrefix(rest[end+1:], ":")
		if !hasPort {
			return "", 0, false
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, false
		}
		return host, p, true
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, false
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, false
	}
	return s[:i], p, true
}

// ssProgram extracts the owning program name from an ss process column
// (`users:(("name",pid=N,fd=M),...)`), returning "" when absent (e.g. when not
// run as root). Only the name is kept — never the PID/FD.
func ssProgram(fields []string) string {
	for _, f := range fields {
		if !strings.HasPrefix(f, "users:(") {
			continue
		}
		open := strings.IndexByte(f, '"')
		if open < 0 {
			return ""
		}
		rest := f[open+1:]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			return ""
		}
		return rest[:end]
	}
	return ""
}

// bindClassForHost classifies a bind address host as wildcard, loopback, or
// routable. A zone suffix (%iface) is ignored.
func bindClassForHost(host string) string {
	switch host {
	case "0.0.0.0", "::", "*", "":
		return "wildcard"
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
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
