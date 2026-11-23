package route

import (
	"io"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ownerGuardTestConn struct {
	N.PacketConn
	writes int
	closed bool
}

func (*ownerGuardTestConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.EOF
}

func (c *ownerGuardTestConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	c.writes++
	buffer.Release()
	return nil
}

func (c *ownerGuardTestConn) Close() error {
	c.closed = true
	return nil
}

func TestUDPOwnerGuardRejectsCachedUploadFromNewOwner(t *testing.T) {
	peer := M.ParseSocksaddr("192.0.2.5:3478")
	upstream := &ownerGuardTestConn{}
	cached := buf.New()
	_, _ = cached.WriteString("packet from a reused socket")
	source := &udpOwnerGuard{
		PacketConn: bufio.NewCachedPacketConn(upstream, cached, peer),
		owner:      &adapter.ConnectionOwner{UserId: 501, ProcessPath: "/test/GroupA"},
		lookup: func(address netip.AddrPort) (*adapter.ConnectionOwner, error) {
			if address != peer.AddrPort() {
				t.Fatalf("lookup used the wrong peer: %v", address)
			}
			return &adapter.ConnectionOwner{UserId: 501, ProcessPath: "/test/GroupB"}, nil
		},
	}
	destination := &ownerGuardTestConn{}
	n, err := bufio.CopyPacket(destination, source)
	if n != 0 || err != errUDPOwnerChanged || !upstream.closed || destination.writes != 0 {
		t.Fatalf("cached upload was not rejected: copied %d bytes, closed %v, writes %d, err %v", n, upstream.closed, destination.writes, err)
	}
}

func TestUDPOwnerGuardRejectsReplyToNewOwner(t *testing.T) {
	peer := M.ParseSocksaddr("[2001:db8::5]:3478")
	upstream := &ownerGuardTestConn{}
	owner := &adapter.ConnectionOwner{UserId: 501, ProcessPath: "/test/GroupA"}
	current := owner
	destination := &udpOwnerGuard{
		PacketConn: upstream,
		owner:      owner,
		lookup: func(address netip.AddrPort) (*adapter.ConnectionOwner, error) {
			if address != peer.AddrPort() {
				t.Fatalf("lookup used the wrong peer: %v", address)
			}
			return current, nil
		},
	}
	if err := destination.WritePacket(buf.New(), peer); err != nil || upstream.writes != 1 || upstream.closed {
		t.Fatalf("reply to the original owner was not delivered: writes %d, closed %v, err %v", upstream.writes, upstream.closed, err)
	}
	current = &adapter.ConnectionOwner{UserId: 501, ProcessPath: "/test/GroupB"}
	if err := destination.WritePacket(buf.New(), peer); err != errUDPOwnerChanged || upstream.writes != 1 || !upstream.closed {
		t.Fatalf("reply to the new owner was not rejected: writes %d, closed %v, err %v", upstream.writes, upstream.closed, err)
	}
}
