package systemconfig

import (
	"net/netip"
	"slices"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestDarwinScopedDNSIsolation(t *testing.T) {
	vpnDNS := M.SocksaddrFrom(netip.MustParseAddr("10.8.0.1"), 53)
	wifiDNS := M.SocksaddrFrom(netip.MustParseAddr("192.168.0.1"), 53)
	info := &dnsInfoConfig{
		generation: 42,
		resolvers: []dnsInfoResolver{
			{domain: "", servers: []M.Socksaddr{vpnDNS}},
		},
		scopedResolvers: []dnsInfoResolver{
			{interfaceIndex: 14, servers: []M.Socksaddr{wifiDNS}},
		},
	}

	// Strict bound interface must use its own scoped resolver, never global VPN DNS.
	wifi := info.buildForInterface(14, true)
	if !slices.Equal(wifi.Servers, []M.Socksaddr{wifiDNS}) {
		t.Fatalf("expected Wi-Fi scoped DNS %v, got %v", wifiDNS, wifi.Servers)
	}
	if wifi.Generation != 42 {
		t.Fatalf("expected generation 42, got %d", wifi.Generation)
	}

	// Strict bound interface with no scoped resolver must NOT leak to global VPN DNS or 127.0.0.1.
	missing := info.buildForInterface(99, true)
	if !slices.Equal(missing.Servers, scopedFallbackServers) {
		t.Fatalf("expected scoped fallback servers %v, got %v", scopedFallbackServers, missing.Servers)
	}

	// Unscoped resolver still uses global VPN DNS when interface has no scoped entry.
	global := info.buildForInterface(99, false)
	if !slices.Equal(global.Servers, []M.Socksaddr{vpnDNS}) {
		t.Fatalf("expected global VPN DNS %v, got %v", vpnDNS, global.Servers)
	}

	// Generation change must change cache signature and equality.
	nextInfo := *info
	nextInfo.generation = 43
	nextWifi := nextInfo.buildForInterface(14, true)
	if wifi.Equal(nextWifi) {
		t.Fatalf("generation bump did not invalidate equality")
	}
	if slices.Equal(wifi.Signature(), nextWifi.Signature()) {
		t.Fatalf("generation bump did not change signature: %v", wifi.Signature())
	}
}
