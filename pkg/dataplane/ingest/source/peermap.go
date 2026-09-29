package source

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// PeerMap assigns a source_id from a sender's address.
//
// It is what makes onboarding a new device a one-line config change rather
// than a new listener. A site's firewalls all send to the same syslog port,
// and a CIDR entry is enough to tell their records apart afterwards.
//
// Longest prefix wins, so a specific host can override the subnet it sits in:
//
//	peer_map:
//	  - {cidr: 10.1.0.0/16,    source_id: site-a}
//	  - {cidr: 10.1.4.0/24,    source_id: site-a-dmz}
//	  - {cidr: 10.1.4.7/32,    source_id: site-a-core-fw}
//
// A peer that matches nothing keeps the listener's own id, so a device that
// starts sending before anyone adds its CIDR is still ingested, just under a
// generic name. Refusing it would drop data over a bookkeeping omission.
type PeerMap struct {
	entries []peerEntry
}

type peerEntry struct {
	prefix   netip.Prefix
	sourceID string
}

// PeerMapEntry is one configured mapping.
type PeerMapEntry struct {
	CIDR     string
	SourceID string
}

// NewPeerMap validates and compiles the mappings. A nil PeerMap is valid and
// matches nothing, so callers need not special-case an empty configuration.
func NewPeerMap(entries []PeerMapEntry) (*PeerMap, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	pm := &PeerMap{}
	for i, e := range entries {
		if e.SourceID == "" {
			return nil, fmt.Errorf("peer_map[%d]: source_id is required", i)
		}
		if !sourceIDPattern.MatchString(e.SourceID) {
			return nil, fmt.Errorf("peer_map[%d]: source_id %q must match %s",
				i, e.SourceID, sourceIDPattern)
		}
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			return nil, fmt.Errorf("peer_map[%d]: %q is not a CIDR: %w", i, e.CIDR, err)
		}
		// Masking normalises 10.1.4.7/24 to 10.1.4.0/24. Without it,
		// Prefix.Contains reports false for everything, which looks like the
		// map silently not working.
		pm.entries = append(pm.entries, peerEntry{prefix: p.Masked(), sourceID: e.SourceID})
	}

	// Sort once, longest prefix first, so Lookup is a linear scan that stops
	// at the first match.
	sort.SliceStable(pm.entries, func(i, j int) bool {
		return pm.entries[i].prefix.Bits() > pm.entries[j].prefix.Bits()
	})
	return pm, nil
}

// Lookup returns the source_id for a peer address, or fallback if nothing
// matches. addr may be "ip:port" or a bare IP.
func (pm *PeerMap) Lookup(addr, fallback string) string {
	if pm == nil || len(pm.entries) == 0 {
		return fallback
	}
	ip, ok := parsePeerIP(addr)
	if !ok {
		return fallback
	}
	for _, e := range pm.entries {
		if e.prefix.Contains(ip) {
			return e.sourceID
		}
	}
	return fallback
}

// parsePeerIP extracts the address from "ip:port" or a bare IP.
func parsePeerIP(addr string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return unmap(ap.Addr()), true
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		return unmap(ip), true
	}
	// A bare IPv6 with no brackets and no port, e.g. "::1".
	if i := strings.LastIndex(addr, ":"); i > 0 {
		if ip, err := netip.ParseAddr(addr[:i]); err == nil {
			return unmap(ip), true
		}
	}
	return netip.Addr{}, false
}

// unmap turns ::ffff:10.1.4.7 into 10.1.4.7, so a dual-stack listener matches
// IPv4 CIDRs. Without it, every peer arriving over a dual-stack socket would
// silently miss every IPv4 rule.
func unmap(a netip.Addr) netip.Addr {
	if a.Is4In6() {
		return a.Unmap()
	}
	return a
}

// Len reports how many mappings are configured.
func (pm *PeerMap) Len() int {
	if pm == nil {
		return 0
	}
	return len(pm.entries)
}
