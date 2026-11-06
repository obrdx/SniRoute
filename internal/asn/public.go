package asn

import "net/netip"

var nonPublic = mustPrefixes(
	"0.0.0.0/8",       // "this network"
	"100.64.0.0/10",   // CGNAT
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"240.0.0.0/4",     // reserved
	"64:ff9b::/96",    // NAT64: may embed private IPv4
	"100::/64",        // discard-only
	"2001:db8::/32",   // documentation
	"2002::/16",       // 6to4: embeds an IPv4 address
)

func mustPrefixes(ps ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ps))
	for i, p := range ps {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// isPublic reports whether ip is a global unicast address outside private,
// loopback, link-local (including cloud metadata 169.254.169.254), multicast,
// CGNAT and documentation/transition ranges.
func isPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
