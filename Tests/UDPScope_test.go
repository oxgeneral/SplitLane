package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func udpScopeTestAddress(index int, addr netip.Addr) *route.InterfaceAddrMessage {
	addrs := make([]route.Addr, unix.RTAX_IFA+1)
	if addr.Is4() {
		addrs[unix.RTAX_IFA] = &route.Inet4Addr{IP: addr.As4()}
	} else {
		addrs[unix.RTAX_IFA] = &route.Inet6Addr{IP: addr.As16()}
	}
	return &route.InterfaceAddrMessage{Index: index, Addrs: addrs}
}

func TestUDPScopeRequiresUniqueActiveSource(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.20")
	v6 := netip.MustParseAddr("2001:db8::20")
	physical := &route.InterfaceMessage{Index: 4, Name: "en0", Flags: unix.IFF_UP}
	vpn := &route.InterfaceMessage{Index: 21, Name: "utun5", Flags: unix.IFF_UP}
	down := &route.InterfaceMessage{Index: vpn.Index, Name: vpn.Name}
	loopback := &route.InterfaceMessage{Index: 1, Name: "lo0", Flags: unix.IFF_UP | unix.IFF_LOOPBACK}
	for _, test := range []struct {
		name     string
		source   netip.Addr
		messages []route.Message
		want     splitWebUDPScope
	}{
		{"IPv4", v4, []route.Message{physical, udpScopeTestAddress(4, v4), vpn}, splitWebUDPScope{"en0", 4}},
		{"IPv6", v6, []route.Message{udpScopeTestAddress(21, v6), vpn}, splitWebUDPScope{"utun5", 21}},
		{"moved", v4, []route.Message{physical, vpn, udpScopeTestAddress(21, v4)}, splitWebUDPScope{"utun5", 21}},
		{"duplicate on same interface", v4, []route.Message{physical, udpScopeTestAddress(4, v4), udpScopeTestAddress(4, v4)}, splitWebUDPScope{"en0", 4}},
		{"missing", v4, []route.Message{physical, udpScopeTestAddress(4, v4.Next())}, splitWebUDPScope{}},
		{"ambiguous", v4, []route.Message{physical, udpScopeTestAddress(4, v4), vpn, udpScopeTestAddress(21, v4)}, splitWebUDPScope{}},
		{"down", v4, []route.Message{down, udpScopeTestAddress(21, v4)}, splitWebUDPScope{}},
		{"down duplicate does not block active", v4, []route.Message{physical, udpScopeTestAddress(4, v4), down, udpScopeTestAddress(21, v4)}, splitWebUDPScope{"en0", 4}},
		{"loopback", v4, []route.Message{loopback, udpScopeTestAddress(1, v4)}, splitWebUDPScope{}},
		{"own TUN", splitWebCaptureIPv6, []route.Message{vpn, udpScopeTestAddress(21, splitWebCaptureIPv6)}, splitWebUDPScope{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := findSplitWebUDPScope(test.messages, test.source)
			if got != test.want || (err == nil) != (test.want.index > 0) {
				t.Fatalf("got %+v, %v, want %+v", got, err, test.want)
			}
		})
	}
}

func TestUDPScopeLocalEchoClosesAfterChange(t *testing.T) {
	for _, direction := range []string{"upload", "download"} {
		t.Run(direction, func(t *testing.T) {
			local := udpScopeTestSocket(t)
			peer := udpScopeTestSocket(t)
			source := netip.MustParseAddr("192.0.2.20")
			current := splitWebUDPScope{"utun5", 21}
			scoped := &splitWebScopedUDPConn{
				PacketConn: local,
				scope:      current,
				source:     source,
				lookup: func(addr netip.Addr) (splitWebUDPScope, error) {
					if addr != source {
						t.Fatalf("lookup used %v instead of %v", addr, source)
					}
					return current, nil
				},
			}
			message := []byte("UDP echo")
			if _, err := scoped.WriteTo(message, peer.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 32)
			n, sender, err := peer.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != string(message) {
				t.Fatalf("upload got %q, %v", buffer[:n], err)
			}
			if _, err := peer.WriteTo(buffer[:n], sender); err != nil {
				t.Fatal(err)
			}
			n, _, err = scoped.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != string(message) {
				t.Fatalf("download got %q, %v", buffer[:n], err)
			}

			if direction == "upload" {
				current.name = "en0"
				n, err = scoped.WriteTo(message, peer.LocalAddr())
			} else {
				if _, err := peer.WriteTo(message, sender); err != nil {
					t.Fatal(err)
				}
				current.index++
				n, _, err = scoped.ReadFrom(buffer)
			}
			if n != 0 || !errors.Is(err, errSplitWebUDPScope) {
				t.Fatalf("changed interface passed %d bytes, %v", n, err)
			}
			if err := local.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("stale socket still open: %v", err)
			}
		})
	}
}

func udpScopeTestSocket(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestUDPScopeDialerBindsAddressAndInterface(t *testing.T) {
	ctx := context.Background()
	d, err := NewDefault(ctx, option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: splitWebOriginalUDPInterface},
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := M.ParseSocksaddr("192.0.2.40:1234")
	if conn, err := d.ListenPacket(ctx, peer); conn != nil || !errors.Is(err, errSplitWebUDPScope) {
		t.Fatalf("listen without TUN source got %v, %v", conn, err)
	}
	if conn, err := d.DialContext(ctx, N.NetworkUDP, peer); conn != nil || !errors.Is(err, errSplitWebUDPScope) {
		t.Fatalf("connected UDP got %v, %v", conn, err)
	}
	source, scope := udpScopeTestLiveAddress(t)
	ctx = adapter.WithContext(ctx, &adapter.InboundContext{
		Inbound: "packet-capture",
		Network: N.NetworkUDP,
		Source:  M.SocksaddrFrom(source, 4321),
	})
	if source.Is6() {
		peer = M.ParseSocksaddr("[2001:db8::40]:1234")
	}
	conn, err := d.ListenPacket(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := M.AddrFromNet(conn.LocalAddr()); got != source {
		t.Fatalf("local address is %v, want %v", got, source)
	}
	fdConn := conn.(*splitWebScopedUDPConn).PacketConn.(*net.UDPConn)
	raw, err := fdConn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Raw(raw, func(fd uintptr) error {
		level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
		if source.Is6() {
			level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		}
		index, err := unix.GetsockoptInt(int(fd), level, option)
		if err == nil && index != scope.index {
			t.Errorf("socket bound to index %d, want %d", index, scope.index)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestUDPScopeOriginalScopeTCPDial(t *testing.T) {
	ctx := context.Background()
	d, err := NewDefault(ctx, option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: splitWebOriginalScopeInterface},
	})
	if err != nil {
		t.Fatal(err)
	}
	source, scope := udpScopeTestLiveAddress(t)
	network := "tcp4"
	if source.Is6() {
		network = "tcp6"
	}
	listener, err := net.Listen(network, netip.AddrPortFrom(source, 0).String())
	if err != nil {
		t.Skipf("cannot listen on %v: %v", source, err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()
	peer := M.SocksaddrFromNet(listener.Addr())
	if conn, err := d.DialContext(ctx, N.NetworkTCP, peer); conn != nil || !errors.Is(err, errSplitWebUDPScope) {
		t.Fatalf("TCP dial without TUN metadata got %v, %v", conn, err)
	}
	tcpCtx := adapter.WithContext(ctx, &adapter.InboundContext{
		Inbound: "packet-capture",
		Network: N.NetworkTCP,
		Source:  M.SocksaddrFrom(source, 4321),
	})
	conn, err := d.DialContext(tcpCtx, N.NetworkTCP, peer)
	if err != nil {
		t.Fatalf("scoped TCP dial failed on %v (%s): %v", source, scope.name, err)
	}
	defer conn.Close()
	if got := M.AddrFromNet(conn.LocalAddr()); got != source {
		t.Fatalf("TCP local address is %v, want %v", got, source)
	}
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Raw(raw, func(fd uintptr) error {
		level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
		if source.Is6() {
			level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		}
		index, err := unix.GetsockoptInt(int(fd), level, option)
		if err == nil && index != scope.index {
			t.Errorf("TCP socket bound to index %d, want %d", index, scope.index)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func udpScopeTestLiveAddress(t testing.TB) (netip.Addr, splitWebUDPScope) {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ip := M.AddrFromNet(addr).Unmap()
		if scope, err := currentSplitWebUDPScope(ip); err == nil {
			return ip, scope
		}
	}
	t.Skip("no unique local IPv4 or IPv6 interface address")
	return netip.Addr{}, splitWebUDPScope{}
}

func BenchmarkUDPScopeSnapshot(b *testing.B) {
	source, want := udpScopeTestLiveAddress(b)
	b.ResetTimer()
	for range b.N {
		got, err := currentSplitWebUDPScope(source)
		if err != nil || got != want {
			b.Fatalf("network changed during the benchmark: got %+v, %v", got, err)
		}
	}
}
