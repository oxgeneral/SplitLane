package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const (
	splitLaneOriginalUDPInterface   = "splitlane-original-udp"
	splitLaneOriginalScopeInterface = "splitlane-original-scope"
)

var (
	errSplitLaneUDPScope = errors.New("original source interface is unavailable or changed")
	splitLaneCaptureIPv4 = netip.MustParseAddr("172.31.252.1")
	splitLaneCaptureIPv6 = netip.MustParseAddr("fd9e:7345:2b1c:252::1")
)

func rejectSplitLaneUnscopedUDP(string, string, syscall.RawConn) error {
	return errSplitLaneUDPScope
}

type splitLaneUDPScope struct {
	name  string
	index int
}

func currentSplitLaneUDPScope(source netip.Addr) (splitLaneUDPScope, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeInterface, 0)
	if err != nil {
		return splitLaneUDPScope{}, err
	}
	messages, err := route.ParseRIB(route.RIBTypeInterface, rib)
	if err != nil {
		return splitLaneUDPScope{}, err
	}
	return findSplitLaneUDPScope(messages, source)
}

func findSplitLaneUDPScope(messages []route.Message, source netip.Addr) (splitLaneUDPScope, error) {
	if !source.IsGlobalUnicast() || source == splitLaneCaptureIPv4 || source == splitLaneCaptureIPv6 {
		return splitLaneUDPScope{}, errSplitLaneUDPScope
	}
	active := make(map[int]string)
	for _, message := range messages {
		if iface, ok := message.(*route.InterfaceMessage); ok && iface.Index > 0 &&
			iface.Name != "" && iface.Flags&unix.IFF_UP != 0 && iface.Flags&unix.IFF_LOOPBACK == 0 {
			active[iface.Index] = iface.Name
		}
	}
	var index int
	for _, message := range messages {
		address, ok := message.(*route.InterfaceAddrMessage)
		if !ok || len(address.Addrs) <= unix.RTAX_IFA {
			continue
		}
		if _, isActive := active[address.Index]; !isActive {
			continue
		}
		var ip netip.Addr
		switch addr := address.Addrs[unix.RTAX_IFA].(type) {
		case *route.Inet4Addr:
			ip = netip.AddrFrom4(addr.IP)
		case *route.Inet6Addr:
			ip = netip.AddrFrom16(addr.IP).Unmap()
		}
		if source == ip {
			if index != 0 && index != address.Index {
				return splitLaneUDPScope{}, errSplitLaneUDPScope
			}
			index = address.Index
		}
	}
	if name, ok := active[index]; ok {
		return splitLaneUDPScope{name: name, index: index}, nil
	}
	return splitLaneUDPScope{}, errSplitLaneUDPScope
}

func (d *DefaultDialer) dialSplitLaneOriginalTCP(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil || metadata.Inbound != "packet-capture" ||
		N.NetworkName(network) != N.NetworkTCP || metadata.Network != N.NetworkTCP || !destination.IsIP() {
		return nil, errSplitLaneUDPScope
	}
	source := metadata.Source.Addr.Unmap()
	if source.BitLen() != destination.Addr.Unmap().BitLen() {
		return nil, errSplitLaneUDPScope
	}
	scope, err := currentSplitLaneUDPScope(source)
	if err != nil {
		return nil, err
	}
	base := d.dialer4.Dialer
	dialNetwork := "tcp4"
	if source.Is6() {
		base = d.dialer6.Dialer
		dialNetwork = "tcp6"
	}
	base.LocalAddr = &net.TCPAddr{IP: source.AsSlice()}
	base.Control = control.BindToInterface(nil, scope.name, scope.index)
	conn, err := base.DialContext(ctx, dialNetwork, destination.String())
	if err != nil {
		return nil, err
	}
	if current, scopeErr := currentSplitLaneUDPScope(source); scopeErr != nil || current != scope {
		_ = conn.Close()
		return nil, errSplitLaneUDPScope
	}
	return d.trackConn(ctx, destination, conn, nil)
}

func (d *DefaultDialer) listenSplitLaneOriginalUDP(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil || metadata.Inbound != "packet-capture" || metadata.Network != N.NetworkUDP || !destination.IsIP() {
		return nil, errSplitLaneUDPScope
	}
	source := metadata.Source.Addr.Unmap()
	if source.BitLen() != destination.Addr.Unmap().BitLen() {
		return nil, errSplitLaneUDPScope
	}
	scope, err := currentSplitLaneUDPScope(source)
	if err != nil {
		return nil, err
	}
	listen := d.udpListener
	listen.Control = control.Append(listen.Control, control.BindToInterface(nil, scope.name, scope.index))
	network := "udp4"
	if source.Is6() {
		network = "udp6"
	}
	conn, err := listen.ListenPacket(ctx, network, netip.AddrPortFrom(source, 0).String())
	if err != nil {
		return nil, err
	}
	scoped := &splitLaneScopedUDPConn{PacketConn: conn, source: source, scope: scope, lookup: currentSplitLaneUDPScope}
	if err := scoped.checkScope(); err != nil {
		return nil, err
	}
	return scoped, nil
}

type splitLaneScopedUDPConn struct {
	net.PacketConn
	source netip.Addr
	scope  splitLaneUDPScope
	lookup func(netip.Addr) (splitLaneUDPScope, error)
}

func (c *splitLaneScopedUDPConn) checkScope() error {
	if scope, err := c.lookup(c.source); err == nil && scope == c.scope {
		return nil
	}
	_ = c.Close()
	return errSplitLaneUDPScope
}

func (c *splitLaneScopedUDPConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	count, addr, err := c.PacketConn.ReadFrom(buffer)
	if count == 0 && err != nil {
		return count, addr, err
	}
	if scopeErr := c.checkScope(); scopeErr != nil {
		return 0, nil, scopeErr
	}
	return count, addr, err
}

func (c *splitLaneScopedUDPConn) WriteTo(buffer []byte, addr net.Addr) (int, error) {
	if err := c.checkScope(); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(buffer, addr)
}
