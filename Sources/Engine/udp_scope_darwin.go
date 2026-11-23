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
	splitWebOriginalUDPInterface   = "splitweb-original-udp"
	splitWebOriginalScopeInterface = "splitweb-original-scope"
)

var (
	errSplitWebUDPScope = errors.New("original source interface is unavailable or changed")
	splitWebCaptureIPv4 = netip.MustParseAddr("172.31.252.1")
	splitWebCaptureIPv6 = netip.MustParseAddr("fd9e:7345:2b1c:252::1")
)

func rejectSplitWebUnscopedUDP(string, string, syscall.RawConn) error {
	return errSplitWebUDPScope
}

type splitWebUDPScope struct {
	name  string
	index int
}

func currentSplitWebUDPScope(source netip.Addr) (splitWebUDPScope, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeInterface, 0)
	if err != nil {
		return splitWebUDPScope{}, err
	}
	messages, err := route.ParseRIB(route.RIBTypeInterface, rib)
	if err != nil {
		return splitWebUDPScope{}, err
	}
	return findSplitWebUDPScope(messages, source)
}

func findSplitWebUDPScope(messages []route.Message, source netip.Addr) (splitWebUDPScope, error) {
	if !source.IsGlobalUnicast() || source == splitWebCaptureIPv4 || source == splitWebCaptureIPv6 {
		return splitWebUDPScope{}, errSplitWebUDPScope
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
				return splitWebUDPScope{}, errSplitWebUDPScope
			}
			index = address.Index
		}
	}
	if name, ok := active[index]; ok {
		return splitWebUDPScope{name: name, index: index}, nil
	}
	return splitWebUDPScope{}, errSplitWebUDPScope
}

func (d *DefaultDialer) dialSplitWebOriginalTCP(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil || metadata.Inbound != "packet-capture" ||
		N.NetworkName(network) != N.NetworkTCP || metadata.Network != N.NetworkTCP || !destination.IsIP() {
		return nil, errSplitWebUDPScope
	}
	source := metadata.Source.Addr.Unmap()
	if source.BitLen() != destination.Addr.Unmap().BitLen() {
		return nil, errSplitWebUDPScope
	}
	scope, err := currentSplitWebUDPScope(source)
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
	if current, scopeErr := currentSplitWebUDPScope(source); scopeErr != nil || current != scope {
		_ = conn.Close()
		return nil, errSplitWebUDPScope
	}
	return d.trackConn(ctx, destination, conn, nil)
}

func (d *DefaultDialer) listenSplitWebOriginalUDP(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil || metadata.Inbound != "packet-capture" || metadata.Network != N.NetworkUDP || !destination.IsIP() {
		return nil, errSplitWebUDPScope
	}
	source := metadata.Source.Addr.Unmap()
	if source.BitLen() != destination.Addr.Unmap().BitLen() {
		return nil, errSplitWebUDPScope
	}
	scope, err := currentSplitWebUDPScope(source)
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
	scoped := &splitWebScopedUDPConn{PacketConn: conn, source: source, scope: scope, lookup: currentSplitWebUDPScope}
	if err := scoped.checkScope(); err != nil {
		return nil, err
	}
	return scoped, nil
}

type splitWebScopedUDPConn struct {
	net.PacketConn
	source netip.Addr
	scope  splitWebUDPScope
	lookup func(netip.Addr) (splitWebUDPScope, error)
}

func (c *splitWebScopedUDPConn) checkScope() error {
	if scope, err := c.lookup(c.source); err == nil && scope == c.scope {
		return nil
	}
	_ = c.Close()
	return errSplitWebUDPScope
}

func (c *splitWebScopedUDPConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	count, addr, err := c.PacketConn.ReadFrom(buffer)
	if count == 0 && err != nil {
		return count, addr, err
	}
	if scopeErr := c.checkScope(); scopeErr != nil {
		return 0, nil, scopeErr
	}
	return count, addr, err
}

func (c *splitWebScopedUDPConn) WriteTo(buffer []byte, addr net.Addr) (int, error) {
	if err := c.checkScope(); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(buffer, addr)
}
