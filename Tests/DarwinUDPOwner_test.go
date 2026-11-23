package process

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

func TestDarwinUDPOwner(t *testing.T) {
	source := netip.MustParseAddrPort("192.0.2.1:50100")
	peer := netip.MustParseAddrPort("198.51.100.5:3478")
	bound := darwinConnectionEntry{
		localAddr: source.Addr(), localPort: source.Port(), remoteAddr: netip.IPv4Unspecified(), pid: 1, uid: 501,
	}
	other := bound
	other.pid = 2
	otherUID := bound
	otherUID.uid = 502
	wildcard := bound
	wildcard.localAddr = netip.IPv4Unspecified()
	exact := bound
	exact.remoteAddr, exact.remotePort = peer.Addr(), peer.Port()
	otherPeer := other
	otherPeer.remoteAddr, otherPeer.remotePort = peer.Addr(), 3479

	for _, test := range []struct {
		name    string
		entries []darwinConnectionEntry
		want    darwinConnectionMatchKind
		reject  bool
	}{
		{name: "bound socket", entries: []darwinConnectionEntry{bound}, want: darwinConnectionMatchLocalFallback},
		{name: "wildcard socket", entries: []darwinConnectionEntry{wildcard}, want: darwinConnectionMatchWildcardFallback},
		{name: "shared port with conflicting owners", entries: []darwinConnectionEntry{bound, other}, reject: true},
		{name: "same process with conflicting socket UIDs", entries: []darwinConnectionEntry{bound, otherUID}, reject: true},
		{name: "exact and unconnected socket from different owners", entries: []darwinConnectionEntry{exact, other}, reject: true},
		{name: "exact and unconnected socket from same owner", entries: []darwinConnectionEntry{bound, exact}, want: darwinConnectionMatchExact},
		{name: "bound and wildcard sockets from same owner", entries: []darwinConnectionEntry{wildcard, bound}, want: darwinConnectionMatchLocalFallback},
		{name: "socket connected elsewhere", entries: []darwinConnectionEntry{otherPeer}, reject: true},
		{name: "ignore unrelated connected socket", entries: []darwinConnectionEntry{otherPeer, bound}, want: darwinConnectionMatchLocalFallback},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner, kind, err := matchDarwinConnectionEntry(test.entries, N.NetworkUDP, source, peer)
			if test.reject {
				if err != ErrNotFound {
					t.Fatalf("expected no owner, got %+v, %v", owner, err)
				}
				return
			}
			if err != nil || owner.pid != bound.pid || kind != test.want {
				t.Fatalf("unexpected owner %+v (%v), %v", owner, kind, err)
			}
		})
	}
}

func TestDarwinUDPOwnerDualStackWildcard(t *testing.T) {
	const port = 50100
	snapshot := make([]byte, darwinXinpgenSize+structSize)
	pcb := snapshot[darwinXinpgenSize:]
	pcb[darwinXinpcbVFlag] = 0x3
	binary.BigEndian.PutUint16(pcb[darwinXinpcbLocalPort:], port)
	binary.NativeEndian.PutUint32(pcb[darwinXsocketOffset+darwinXsocketLastPID:], 123)
	entries := parseDarwinSnapshot(snapshot, structSize)
	for _, addressPair := range [][2]string{{"192.0.2.1", "192.0.2.2"}, {"2001:db8::1", "2001:db8::2"}} {
		source := netip.AddrPortFrom(netip.MustParseAddr(addressPair[0]), port)
		peer := netip.AddrPortFrom(netip.MustParseAddr(addressPair[1]), 3478)
		owner, kind, err := matchDarwinConnectionEntry(entries, N.NetworkUDP, source, peer)
		if err != nil || owner.pid != 123 || kind != darwinConnectionMatchWildcardFallback {
			t.Fatalf("no dual-stack wildcard owner for %s: %+v (%v), %v", source, owner, kind, err)
		}
	}
}

func TestDarwinUDPOwnerRefreshesSnapshot(t *testing.T) {
	source := netip.MustParseAddrPort("[2001:db8::1]:50100")
	peer := netip.MustParseAddrPort("[2001:db8::2]:3478")
	finder := newDarwinConnectionFinder(time.Hour)
	uid := int32(500)
	finder.builder = func(string) (darwinSnapshot, error) {
		uid++
		return darwinSnapshot{createdAt: time.Now(), entries: []darwinConnectionEntry{{
			localAddr: source.Addr(), localPort: source.Port(), remoteAddr: peer.Addr(), remotePort: peer.Port(), uid: uid,
		}}}, nil
	}
	for _, want := range []int32{501, 502} {
		owner, err := finder.find(N.NetworkUDP, source, peer)
		if err != nil || owner.UserId != want {
			t.Fatalf("expected current socket owner %v, got %+v, %v", want, owner, err)
		}
	}
}

func TestDarwinTCPOwnerRefreshesSnapshotAndResolvesLivePID(t *testing.T) {
	source := netip.MustParseAddrPort("127.0.0.1:50100")
	peer := netip.MustParseAddrPort("127.0.0.1:39878")
	finder := newDarwinConnectionFinder(time.Hour)
	uid := int32(500)
	finder.builder = func(string) (darwinSnapshot, error) {
		uid++
		return darwinSnapshot{createdAt: time.Now(), entries: []darwinConnectionEntry{
			{localAddr: source.Addr(), localPort: source.Port(), remoteAddr: peer.Addr(), remotePort: peer.Port(), pid: 0, uid: 0},
			{localAddr: source.Addr(), localPort: source.Port(), remoteAddr: peer.Addr(), remotePort: peer.Port(), pid: 42, uid: uid},
		}}, nil
	}
	for _, want := range []int32{501, 502} {
		owner, err := finder.find(N.NetworkTCP, source, peer)
		if err != nil || owner.UserId != want {
			t.Fatalf("expected current TCP socket owner %v, got %+v, %v", want, owner, err)
		}
	}
}

func TestDarwinResolveAppOwner(t *testing.T) {
	responsible := func(pid uint32) uint32 {
		switch pid {
		case 10, 11, 12:
			return 20
		case 13:
			return 21
		default:
			return 0
		}
	}
	execPath := func(pid uint32) (string, error) {
		switch pid {
		case 20:
			return "/Applications/Codex.app/Contents/MacOS/Codex", nil
		case 21:
			return "/usr/sbin/some-daemon", nil
		default:
			return "", ErrNotFound
		}
	}
	if got := resolveAppOwner(10, "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking", responsible, execPath); got != "/Applications/Codex.app/Contents/MacOS/Codex" {
		t.Fatalf("WebKit XPC not attributed to app: %q", got)
	}
	if got := resolveAppOwner(11, "/usr/bin/curl", responsible, execPath); got != "/Applications/Codex.app/Contents/MacOS/Codex" {
		t.Fatalf("child CLI not attributed to app: %q", got)
	}
	if got := resolveAppOwner(12, "/Applications/Chrome.app/Contents/MacOS/Chrome", responsible, execPath); got != "/Applications/Chrome.app/Contents/MacOS/Chrome" {
		t.Fatalf("app bundle path must not be overridden: %q", got)
	}
	if got := resolveAppOwner(13, "/usr/bin/curl", responsible, execPath); got != "/usr/bin/curl" {
		t.Fatalf("non-app responsible owner must keep original path: %q", got)
	}
}

func BenchmarkDarwinUDPOwnerLookup(b *testing.B) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer socket.Close()
	source := socket.LocalAddr().(*net.UDPAddr).AddrPort()
	peer := netip.MustParseAddrPort("127.0.0.1:3478")
	finder := newDarwinConnectionFinder(darwinSnapshotTTL)
	for b.Loop() {
		if _, err := finder.find(N.NetworkUDP, source, peer); err != nil {
			b.Fatal(err)
		}
	}
}
