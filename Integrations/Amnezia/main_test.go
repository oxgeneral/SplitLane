package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/miekg/dns"
)

func TestPrivateProxy(t *testing.T) {
	peerKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	insideIP := netip.MustParseAddr("192.0.2.2")
	tun, stack, err := netstack.CreateNetTUN([]netip.Addr{insideIP}, nil, 1408)
	if err != nil {
		t.Fatal(err)
	}
	peer := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer peer.Close()
	peerIPC := fmt.Sprintf("private_key=%x\npublic_key=%x\nallowed_ip=192.0.2.1/32\n",
		peerKey.Bytes(), clientKey.PublicKey().Bytes())
	if err := peer.IpcSet(peerIPC); err != nil {
		t.Fatal(err)
	}
	if err := peer.Up(); err != nil {
		t.Fatal(err)
	}
	info, err := peer.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port int
	for _, line := range strings.Split(info, "\n") {
		if number, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err = strconv.Atoi(number)
			if err != nil {
				t.Fatal("invalid synthetic peer port")
			}
		}
	}
	if port == 0 {
		t.Fatal("synthetic peer has no port")
	}
	web, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(insideIP, 8080))
	if err != nil {
		t.Fatal(err)
	}
	webServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "through Amnezia")
	})}
	go webServer.Serve(web)
	defer webServer.Close()

	udp, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(insideIP, 53))
	if err != nil {
		t.Fatal(err)
	}
	dnsServer := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		response := new(dns.Msg).SetReply(req)
		if len(req.Question) == 1 && req.Question[0].Name == "private.test." && req.Question[0].Qtype == dns.TypeA {
			a, _ := dns.NewRR("private.test. 1 IN A 192.0.2.2")
			response.Answer = []dns.RR{a}
		}
		w.WriteMsg(response)
	})}
	go dnsServer.ActivateAndServe()
	defer dnsServer.Shutdown()

	profile, err := json.Marshal(map[string]any{
		"privateKey":       base64.StdEncoding.EncodeToString(clientKey.Bytes()),
		"serverPublicKey":  base64.StdEncoding.EncodeToString(peerKey.PublicKey().Bytes()),
		"serverIpv4AddrIn": "127.0.0.1", "serverPort": port,
		"deviceIpv4Address": "192.0.2.1", "primaryDnsServer": insideIP.String(),
		"allowedIPAddressRanges": []map[string]any{{"address": insideIP.String(), "range": 32}},
	})
	if err != nil {
		t.Fatal(err)
	}
	options, err := engineOptions(profile, "lo0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	engine, err := startEngine(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	dir, err := os.MkdirTemp("/tmp", "swawg")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	done := make(chan error, 1)
	go func() { done <- serve(ctx, engine.Router(), dir) }()
	path := filepath.Join(dir, "amnezia.sock")
	var client net.Conn
	for i := 0; i < 50; i++ {
		client, err = net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(client, "CONNECT private.test:8080 HTTP/1.1\r\nHost: private.test:8080\r\n\r\n")
	reader := bufio.NewReader(client)
	connected, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || connected.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT failed: %v", err)
	}
	fmt.Fprint(client, "GET / HTTP/1.1\r\nHost: private.test\r\nConnection: close\r\n\r\n")
	reply, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Body.Close()
	body, err := io.ReadAll(reply.Body)
	if err != nil || string(body) != "through Amnezia" {
		t.Fatalf("AWG HTTP response = %q, error = %v", body, err)
	}
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not stop")
	}
	if next, err := net.DialTimeout("unix", path, 100*time.Millisecond); err == nil {
		next.Close()
		t.Fatal("a stopped Amnezia route accepted a new connection")
	}
}
