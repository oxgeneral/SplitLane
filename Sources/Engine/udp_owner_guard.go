package route

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var errUDPOwnerChanged = errors.New("UDP socket owner changed or could not be identified")

type udpOwnerGuard struct {
	N.PacketConn
	owner  *adapter.ConnectionOwner
	lookup func(netip.AddrPort) (*adapter.ConnectionOwner, error)
}

func (r *Router) guardPacketOwner(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) N.PacketConn {
	source := metadata.Source.AddrPort()
	return &udpOwnerGuard{
		PacketConn: conn,
		owner:      metadata.ProcessInfo,
		lookup: func(peer netip.AddrPort) (*adapter.ConnectionOwner, error) {
			if r.processSearcher == nil {
				return nil, errUDPOwnerChanged
			}
			return r.processSearcher.FindProcessInfo(ctx, N.NetworkUDP, source, peer)
		},
	}
}

func (c *udpOwnerGuard) checkOwner(peer M.Socksaddr) error {
	if c.owner != nil && c.owner.ProcessPath != "" && peer.IsIP() {
		current, err := c.lookup(peer.AddrPort())
		if err == nil && current != nil && current.UserId == c.owner.UserId && current.ProcessPath == c.owner.ProcessPath {
			return nil
		}
	}
	// Close the NAT session so the next packet is classified again.
	_ = c.Close()
	return errUDPOwnerChanged
}

func (c *udpOwnerGuard) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	peer, err := c.PacketConn.ReadPacket(buffer)
	if err != nil {
		return peer, err
	}
	return peer, c.checkOwner(peer)
}

func (c *udpOwnerGuard) WritePacket(buffer *buf.Buffer, peer M.Socksaddr) error {
	if err := c.checkOwner(peer); err != nil {
		buffer.Release()
		return err
	}
	return c.PacketConn.WritePacket(buffer, peer)
}

func (c *udpOwnerGuard) PacketConnHandshakeSuccess(conn net.PacketConn) error {
	return N.ReportPacketConnHandshakeSuccess(c.PacketConn, conn)
}

func (c *udpOwnerGuard) HandshakeFailure(err error) error {
	var reportErr error
	if upstream, ok := common.Cast[N.HandshakeFailure](c.PacketConn); ok {
		reportErr = upstream.HandshakeFailure(err)
	}
	return errors.Join(reportErr, c.Close())
}
