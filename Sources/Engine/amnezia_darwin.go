package dialer

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

func splitWebAmneziaDialer(binding string) N.Dialer {
	if binding != "splitweb-amnezia" {
		return nil
	}
	return amneziaDialer{}
}

type amneziaDialer struct{}

func (amneziaDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("the local Amnezia connection requires TCP")
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(base, "SplitWebOnMac")
	state, err := os.Lstat(dir)
	if err != nil || !state.IsDir() || state.Mode().Perm()&0077 != 0 ||
		state.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("the private Amnezia connection is unavailable")
	}
	socket := filepath.Join(dir, "amnezia.sock")
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	raw, err := conn.(*net.UnixConn).SyscallConn()
	var peer *unix.Xucred
	if err == nil {
		err = raw.Control(func(fd uintptr) {
			peer, _ = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		})
	}
	if err != nil || peer == nil || peer.Uid != uint32(os.Geteuid()) {
		conn.Close()
		return nil, errors.New("unexpected owner of the Amnezia connection")
	}
	return conn, nil
}

func (amneziaDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
