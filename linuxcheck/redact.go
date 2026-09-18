// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
)

// Default network-prefix lengths used when reducing an address to a prefix. IPv4
// keeps the /24 network; IPv6 keeps the /48 site prefix.
const (
	defaultV4PrefixBits = 24
	defaultV6PrefixBits = 48
)

// Redactor applies the report's redaction policy consistently across collectors:
// a salted hash for values that must be diffable but not disclosed (usernames,
// key material identifiers), and prefix reduction for IP addresses. Using one
// Redactor everywhere is what keeps redaction uniform.
//
// The salt makes hashes stable within a host (so a value diffs equal across
// reports) while preventing precomputation and cross-host correlation. The
// harness supplies a per-host salt; a zero-value Redactor hashes without a salt.
type Redactor struct {
	salt []byte
}

// NewRedactor returns a Redactor using salt for its hashes.
func NewRedactor(salt []byte) *Redactor {
	return &Redactor{salt: slices.Clone(salt)}
}

// Hash returns a stable, salted hex digest of s, suitable for diffing without
// revealing the value. An empty string hashes to an empty string.
func (r *Redactor) Hash(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.New()
	h.Write(r.salt)
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// HashAll returns the salted digests of every element of ss, preserving order.
func (r *Redactor) HashAll(ss []string) []string {
	if ss == nil {
		return nil
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = r.Hash(s)
	}
	return out
}

// PrefixAddr reduces addr to its default network prefix (masked), so an exact
// address is never emitted while a change of network is still detectable.
func PrefixAddr(addr netip.Addr) netip.Prefix {
	bits := defaultV6PrefixBits
	if addr.Is4() {
		bits = defaultV4PrefixBits
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return p
}

// PrefixIP parses an IP string and returns its default network prefix in CIDR
// form (e.g. "203.0.113.7" -> "203.0.113.0/24"), reporting false if s is not a
// valid address.
func PrefixIP(s string) (string, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	p := PrefixAddr(addr)
	if !p.IsValid() {
		return "", false
	}
	return p.String(), true
}
