package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	boxjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	proxy "github.com/sagernet/sing/protocol/http"
	"golang.org/x/sys/unix"
)

type activation struct {
	PrivateKey             string
	ServerPublicKey        string
	ServerPskKey           string
	ServerIpv4AddrIn       string
	ServerPort             uint16
	DeviceIpv4Address      string
	DeviceIpv6Address      string
	PrimaryDnsServer       string
	SecondaryDnsServer     string
	AllowedIPAddressRanges []struct {
		Address string
		Range   int
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Не удалось открыть отдельное подключение AmneziaVPN.")
		os.Exit(1)
	}
}

func run() error {
	if os.Geteuid() == 0 {
		return errors.New("the helper must run as the current user")
	}
	input := bufio.NewReaderSize(os.Stdin, 64*1024)
	data, err := input.ReadSlice('\n')
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		_, _ = io.Copy(io.Discard, input)
		stop()
	}()

	interfaceName, err := physicalDefault()
	if err != nil {
		return err
	}
	options, err := engineOptions(data, interfaceName)
	if err != nil {
		return err
	}
	engine, err := startEngine(ctx, options)
	if err != nil {
		return err
	}
	defer engine.Close()
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	unix.Umask(0077)
	return serve(ctx, engine.Router(), filepath.Join(base, "SplitLane"))
}

func startEngine(ctx context.Context, options []byte) (*box.Box, error) {
	ctx = include.Context(ctx)
	config, err := boxjson.UnmarshalExtendedContext[option.Options](ctx, options)
	if err != nil {
		return nil, err
	}
	engine, err := box.New(box.Options{Options: config, Context: ctx})
	if err != nil {
		return nil, err
	}
	if err := engine.Start(); err != nil {
		engine.Close()
		return nil, err
	}
	return engine, nil
}

func physicalDefault() (string, error) {
	data, err := exec.Command("/usr/sbin/netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return "", err
	}
	var fallback string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "default" || !strings.HasPrefix(fields[3], "en") {
			continue
		}
		if _, err := strconv.Atoi(fields[3][2:]); err != nil {
			continue
		}
		dev, err := net.InterfaceByName(fields[3])
		if err != nil || dev.Flags&net.FlagUp == 0 {
			continue
		}
		if fallback == "" {
			fallback = dev.Name
		}
		if strings.HasPrefix(fields[1], "link#") || dev.Flags&net.FlagRunning == 0 {
			continue
		}
		if addrs, err := dev.Addrs(); err == nil {
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLinkLocalUnicast() {
					return dev.Name, nil
				}
			}
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", errors.New("no physical IPv4 route")
}

func engineOptions(data []byte, interfaceName string) ([]byte, error) {
	var profile activation
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if endpoint, err := netip.ParseAddr(profile.ServerIpv4AddrIn); err != nil || !endpoint.Is4() || profile.ServerPort == 0 {
		return nil, errors.New("invalid Amnezia peer")
	}
	if profile.PrivateKey == "" || profile.ServerPublicKey == "" {
		return nil, errors.New("Amnezia profile has no keys")
	}
	for _, key := range []string{profile.PrivateKey, profile.ServerPublicKey, profile.ServerPskKey} {
		if key == "" {
			continue
		}
		if decoded, err := base64.StdEncoding.DecodeString(key); err != nil || len(decoded) != 32 {
			return nil, errors.New("invalid Amnezia key")
		}
	}
	var addresses, allowed []string
	for _, value := range []string{profile.DeviceIpv4Address, profile.DeviceIpv6Address} {
		if value == "" {
			continue
		}
		if ip, err := netip.ParseAddr(value); err == nil {
			value = netip.PrefixFrom(ip, ip.BitLen()).String()
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, prefix.String())
	}
	for _, value := range profile.AllowedIPAddressRanges {
		prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", value.Address, value.Range))
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, prefix.Masked().String())
	}
	if len(addresses) == 0 || len(allowed) == 0 {
		return nil, errors.New("Amnezia profile has no tunnel addresses")
	}
	peer := map[string]any{"address": profile.ServerIpv4AddrIn, "port": profile.ServerPort,
		"public_key": profile.ServerPublicKey, "preshared_key": profile.ServerPskKey, "allowed_ips": allowed}
	endpoint := map[string]any{"type": "awg", "tag": "amnezia", "useIntegratedTun": false,
		"private_key": profile.PrivateKey, "address": addresses, "bind_interface": interfaceName,
		"peers": []any{peer}}
	if err := addParameters(raw, endpoint, peer); err != nil {
		return nil, err
	}
	var dnsServer string
	for _, candidate := range []string{profile.PrimaryDnsServer, profile.SecondaryDnsServer} {
		if addr, err := netip.ParseAddr(candidate); err == nil && !addr.IsUnspecified() {
			dnsServer = addr.String()
			break
		}
	}
	if dnsServer == "" {
		return nil, errors.New("Amnezia profile has no DNS server")
	}
	return json.Marshal(map[string]any{
		"log":       map[string]any{"disabled": true},
		"endpoints": []any{endpoint},
		"dns": map[string]any{"servers": []any{
			map[string]any{"type": "udp", "tag": "amnezia-dns", "server": dnsServer, "detour": "amnezia"},
		}},
		"route": map[string]any{"final": "amnezia", "rules": []any{
			map[string]any{"action": "resolve", "server": "amnezia-dns"},
		}},
	})
}

func addParameters(raw map[string]json.RawMessage, endpoint, peer map[string]any) error {
	for name, field := range raw {
		var value string
		if len(field) > 0 && field[0] == '"' {
			if err := json.Unmarshal(field, &value); err != nil {
				return err
			}
		} else {
			value = string(field)
		}
		if value == "" || value == "null" {
			continue
		}
		switch name {
		case "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "deviceMTU", "persistentKeepalive":
			n, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return errors.New("invalid Amnezia numeric parameter")
			}
			switch name {
			case "deviceMTU":
				endpoint["mtu"] = n
			case "persistentKeepalive":
				peer["persistent_keepalive_interval"] = n
			default:
				endpoint[strings.ToLower(name)] = n
			}
		case "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5":
			endpoint[strings.ToLower(name)] = value
		case "HeaderProtectionKey":
			endpoint["header_protection_key"] = value
		case "ContentPaddingAddition":
			endpoint["content_padding_addition"] = value
		case "RekeyAfterTime":
			endpoint["rekey_after_time"] = value
		case "RekeyTimeout":
			endpoint["rekey_timeout"] = value
		case "RejectAfterTime":
			endpoint["reject_after_time"] = value
		case "KeepaliveTimeout":
			endpoint["keepalive_timeout"] = value
		case "MaxHandshakeAttempts":
			endpoint["max_handshake_attempts"] = value
		case "RandomTrailers", "DisableCookies":
			enabled := false
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "true", "1", "on", "yes", "t":
				enabled = true
			case "false", "0", "off", "no", "f":
			default:
				return errors.New("invalid Amnezia switch")
			}
			if name == "RandomTrailers" {
				endpoint["random_trailers"] = enabled
			} else {
				endpoint["disable_cookies"] = enabled
			}
		default:
			continue
		}
		if strings.ContainsAny(value, "\r\n") {
			return errors.New("invalid Amnezia parameter")
		}
	}
	return nil
}

func serve(ctx context.Context, router adapter.ConnectionRouterEx, dir string) error {
	if ctx.Err() != nil {
		return nil
	}
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	state, err := os.Lstat(dir)
	if err != nil || !state.IsDir() || state.Mode().Perm()&0077 != 0 ||
		state.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("Amnezia socket directory is not private")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "amnezia.lock"), os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	path := filepath.Join(dir, "amnezia.sock")
	if old, err := os.Lstat(path); err == nil {
		if old.Mode()&os.ModeSocket == 0 || old.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return errors.New("unexpected file in place of Amnezia socket")
		}
		active, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			active.Close()
			return errors.New("Amnezia socket is already active")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	fmt.Println("ready")
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handle(ctx, conn, router)
	}
}

type connectionHandler struct {
	router adapter.ConnectionRouterEx
}

func (h connectionHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.SetReadDeadline(time.Time{})
	h.router.RouteConnectionEx(ctx, conn, adapter.InboundContext{Source: source, Destination: destination}, onClose)
}

func handle(ctx context.Context, conn net.Conn, router adapter.ConnectionRouterEx) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	finish := N.OnceClose(func(error) {
		stop()
		conn.Close()
	})
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := proxy.HandleConnectionEx(ctx, conn, bufio.NewReader(conn), nil, connectionHandler{router}, M.Socksaddr{}, finish); err != nil {
		finish(err)
	}
}
