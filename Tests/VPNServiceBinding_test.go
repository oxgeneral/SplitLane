package dialer

import (
	"net"
	"os"
	"testing"

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
