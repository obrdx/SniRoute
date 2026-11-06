package asn

import (
	"net/netip"
	"testing"
)

func TestPublicAddressPolicy(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !isPublic(netip.MustParseAddr(s)) {
			t.Errorf("public address rejected: %s", s)
		}
	}
	for _, s := range []string{"0.0.0.0", "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "240.0.0.1", "224.0.0.1", "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "64:ff9b::a00:1", "2002:a00:1::", "::ffff:127.0.0.1"} {
		if isPublic(netip.MustParseAddr(s)) {
			t.Errorf("non-public address would be disclosed to ASN service: %s", s)
		}
	}
	if isPublic(netip.Addr{}) {
		t.Error("invalid address accepted")
	}
}
