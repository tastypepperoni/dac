package dac

import "net/netip"

// Special-purpose address blocks from the IANA IPv4 and IPv6 Special-Purpose
// Address Registries (RFC 6890 and updates).  §7.2: a verifier MUST NOT connect
// to addresses that the registries mark as not globally reachable.
//
// globalExceptions are more specific entries that the registries mark as
// globally reachable inside a block that is not; they are checked first.
var globalExceptions = mustPrefixes(
	"192.0.0.9/32",    // Port Control Protocol Anycast
	"192.0.0.10/32",   // Traversal Using Relays around NAT Anycast
	"2001:1::1/128",   // Port Control Protocol Anycast
	"2001:1::2/128",   // Traversal Using Relays around NAT Anycast
	"2001:1::3/128",   // DNS-SD Service Registration Protocol Anycast
	"2001:3::/32",     // AMT
	"2001:4:112::/48", // AS112-v6
	"2001:20::/28",    // ORCHIDv2
	"2001:30::/28",    // Drone Remote ID Protocol Entity Tags (DETs) Prefix
)

// notGlobal are the blocks marked "Globally Reachable: False" (or not
// applicable to unicast use), plus multicast, which is never a valid server.
var notGlobal = mustPrefixes(
	// IPv4
	"0.0.0.0/8",          // "This network"
	"10.0.0.0/8",         // Private-Use
	"100.64.0.0/10",      // Shared Address Space
	"127.0.0.0/8",        // Loopback
	"169.254.0.0/16",     // Link Local
	"172.16.0.0/12",      // Private-Use
	"192.0.0.0/24",       // IETF Protocol Assignments (exceptions above)
	"192.0.2.0/24",       // Documentation (TEST-NET-1)
	"192.88.99.0/24",     // Deprecated 6to4 Relay Anycast
	"192.168.0.0/16",     // Private-Use
	"198.18.0.0/15",      // Benchmarking
	"198.51.100.0/24",    // Documentation (TEST-NET-2)
	"203.0.113.0/24",     // Documentation (TEST-NET-3)
	"224.0.0.0/4",        // Multicast
	"240.0.0.0/4",        // Reserved
	"255.255.255.255/32", // Limited Broadcast
	// IPv6
	"::/128",         // Unspecified Address
	"::1/128",        // Loopback Address
	"::ffff:0:0/96",  // IPv4-mapped Address
	"64:ff9b:1::/48", // IPv4-IPv6 Translation (local use)
	"100::/64",       // Discard-Only Address Block
	"100:0:0:1::/64", // Dummy IPv6 Prefix
	"2001::/23",      // IETF Protocol Assignments (exceptions above)
	"2001:db8::/32",  // Documentation
	"2002::/16",      // 6to4
	"3fff::/20",      // Documentation
	"5f00::/16",      // Segment Routing (SRv6) SIDs
	"fc00::/7",       // Unique-Local
	"fe80::/10",      // Link-Local Unicast
	"ff00::/8",       // Multicast
)

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s))
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// GloballyReachable reports whether a may be connected to under §7.2.
func GloballyReachable(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" {
		return false
	}
	// Resolvers may return IPv4 addresses in IPv4-mapped form; the connection
	// then goes to the IPv4 address, which is what is checked (and dialled).
	a = a.Unmap()
	// NAT64 (64:ff9b::/96) is globally reachable in the registry, but on a
	// NAT64 network it reaches the embedded IPv4 address, which is checked too.
	if nat64.Contains(a) {
		b := a.As16()
		if !GloballyReachable(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})) {
			return false
		}
	}
	for _, p := range globalExceptions {
		if p.Contains(a) {
			return true
		}
	}
	for _, p := range notGlobal {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
