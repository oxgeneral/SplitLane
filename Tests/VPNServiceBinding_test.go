package dialer

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

func TestSplitLaneVPNServiceRebind(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var other int
	for _, iface := range interfaces {
		if iface.Index != loopback.Index {
			other = iface.Index
			break
		}
	}
	if other == 0 {
		t.Skip("interface rebind fixture needs two local interface indexes")
	}
	services := map[string]int{"service-a": loopback.Index, "service-b": other}
	bind := splitLaneVPNControl("service-a", true, func(id string, exact bool) int {
		if !exact || id != "service-a" {
			t.Fatalf("expected exact service-a lookup, got %q (exact %v)", id, exact)
		}
		return services[id]
	})
	checkVPNServiceBinding(t, bind, loopback.Index)

	// Another service can take the previous interface while the selected one is offline.
	delete(services, "service-a")
	services["service-b"] = loopback.Index
	checkVPNServiceBinding(t, bind, 0)
	services["service-a"] = other
	checkVPNServiceBinding(t, bind, other)
}

func TestSplitLaneVPNMissingService(t *testing.T) {
	bind := splitLaneBindInterface(nil, "splitlane-vpn-service:00000000-0000-0000-0000-000000000000")
	checkVPNServiceBinding(t, bind, 0)
}

func TestSplitLaneVPNResolverSerializationAndCache(t *testing.T) {
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	var calls atomic.Int32
	var currentIndex atomic.Int32
	currentIndex.Store(32)

	var clockMu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	readClock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	resolver := newVPNResolver(func(target string, service bool) int {
		n := inFlight.Add(1)
		for {
			prev := maxInFlight.Load()
			if n <= prev || maxInFlight.CompareAndSwap(prev, n) {
				break
			}
		}
		calls.Add(1)
		time.Sleep(2 * time.Millisecond)
		inFlight.Add(-1)
		return int(currentIndex.Load())
	}, readClock)

	// Burst of parallel lookups across different targets must never overlap inside query.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		target := "provider-a"
		if i%2 == 1 {
			target = "provider-b"
		}
		go func(tgt string) {
			defer wg.Done()
			if got := resolver.resolve(tgt, false); got != 32 {
				t.Errorf("expected interface 32, got %d", got)
			}
		}(target)
	}
	wg.Wait()

	if got := maxInFlight.Load(); got != 1 {
		t.Fatalf("expected serialized queries (max in-flight 1), got %d", got)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 cached queries (one per target), got %d", got)
	}

	// After TTL expires, resolver re-queries and picks up disconnect immediately.
	advance(vpnResolveCacheTTL + time.Millisecond)
	currentIndex.Store(0)
	if got := resolver.resolve("provider-a", false); got != 0 {
		t.Fatalf("expected disconnected (0), got %d", got)
	}

	// Disconnected (0) must never be cached so reconnect succeeds without waiting for TTL.
	currentIndex.Store(41)
	if got := resolver.resolve("provider-a", false); got != 41 {
		t.Fatalf("expected immediate reconnect (41), got %d", got)
	}
}

func checkVPNServiceBinding(t *testing.T, bind control.Func, expected int) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	socket := os.NewFile(uintptr(fd), "VPN binding test socket")
	defer socket.Close()
	conn, err := socket.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	err = bind("udp4", "127.0.0.1:9", conn)
	if expected == 0 {
		if err == nil || err.Error() != "VPN profile is not connected" {
			t.Fatalf("expected unavailable VPN profile, got %v", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	index, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF)
	if err != nil || index != expected {
		t.Fatalf("expected bound interface %d, got %d, %v", expected, index, err)
	}
}
