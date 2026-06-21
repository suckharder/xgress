//go:build integration

package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/traefikcfg"
)

// TestStreamRouting proves xgress's L4 (stream) hosts route raw TCP and UDP through a
// real Traefik: a stream entrypoint declared in the static config is bound by
// Traefik, and the rendered tcp:/udp: routers+services forward real bytes to an
// upstream. It's kept separate from TestConfigContract so that test can keep
// asserting empty TCP/UDP pruning (A4) — here those sections are populated.
func TestStreamRouting(t *testing.T) {
	h := newContractHarness(t)
	ctx := context.Background()

	tcpHost, tcpPort := startTCPEcho(t)
	udpHost, udpPort := startUDPEcho(t)

	// Ports: web, websecure, api (Traefik always needs these), + one per stream EP.
	p := freePorts(t, 5)
	webPort, httpsPort, apiPort, tcpEP, udpEP := p[0], p[1], p[2], p[3], p[4]

	// Seed stream hosts pointing at the echo servers.
	tcpStream := &store.Host{
		Kind: store.HostKindStream, Enabled: true,
		StreamProto: "tcp", StreamEntryPoint: "streamtcp",
		Upstreams: []store.Upstream{{Host: h.env.reachable(tcpHost), Port: tcpPort}},
	}
	if err := h.st.CreateHost(ctx, tcpStream); err != nil {
		t.Fatalf("create tcp stream host: %v", err)
	}
	udpStream := &store.Host{
		Kind: store.HostKindStream, Enabled: true,
		StreamProto: "udp", StreamEntryPoint: "streamudp",
		Upstreams: []store.Upstream{{Host: h.env.reachable(udpHost), Port: udpPort}},
	}
	if err := h.st.CreateHost(ctx, udpStream); err != nil {
		t.Fatalf("create udp stream host: %v", err)
	}
	if _, err := h.eng.Reload(ctx); err != nil {
		t.Fatalf("engine.Reload: %v", err)
	}

	params := traefikcfg.StaticParams{
		HTTPEntryPoint:   "web",
		HTTPSEntryPoint:  "websecure",
		HTTPPort:         webPort,
		HTTPSPort:        httpsPort,
		ProviderEndpoint: h.provider,
		ProviderToken:    h.cfg.ProviderToken,
		PollInterval:     "1s",
		APIListen:        fmt.Sprintf("127.0.0.1:%d", apiPort),
		LogLevel:         "INFO",
		StreamEntryPoints: []config.StreamEntryPoint{
			{Name: "streamtcp", Proto: "tcp", Port: tcpEP},
			{Name: "streamudp", Proto: "udp", Port: udpEP},
		},
	}
	eps, stop := h.env.run(t, params)
	defer stop()

	// S1 — TCP: a connection to Traefik's TCP entrypoint round-trips through to the
	// echo upstream. Polled: until Traefik loads the tcp router (~1s), the entrypoint
	// accepts but immediately closes the connection.
	eventually(t, 8*time.Second, func() error {
		return echoRoundTripTCP(fmt.Sprintf("127.0.0.1:%d", tcpEP), "xgress-tcp-stream-nonce")
	})

	// S3 — UDP: a datagram to Traefik's UDP entrypoint is forwarded and echoed back.
	eventually(t, 8*time.Second, func() error {
		return echoRoundTripUDP(fmt.Sprintf("127.0.0.1:%d", udpEP), "xgress-udp-stream-nonce")
	})

	// Populated tcp:/udp: sections must load cleanly in real Traefik (complements A4,
	// which proves the empty ones are pruned).
	logs := eps.logs.String()
	for _, bad := range []string{"standalone element", "cannot decode configuration", "error while building configuration"} {
		if strings.Contains(logs, bad) {
			t.Errorf("Traefik reported a config-decode problem (%q) on a populated stream section:\n%s", bad, logs)
		}
	}
}

// echoRoundTripTCP dials addr, sends nonce, and verifies it is echoed back.
func echoRoundTripTCP(addr, nonce string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(nonce)); err != nil {
		return err
	}
	buf := make([]byte, len(nonce))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != nonce {
		return fmt.Errorf("tcp echo mismatch: got %q want %q", buf, nonce)
	}
	return nil
}

// echoRoundTripUDP sends a datagram to addr and verifies it is echoed back.
func echoRoundTripUDP(addr, nonce string) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(nonce)); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != nonce {
		return fmt.Errorf("udp echo mismatch: got %q want %q", buf[:n], nonce)
	}
	return nil
}

// startTCPEcho runs an in-process TCP echo server on loopback, returning its host
// and port. Each connection is echoed byte-for-byte until closed.
func startTCPEcho(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", a.Port
}

// startUDPEcho runs an in-process UDP echo server on loopback, returning its host
// and port. Each datagram is echoed back to its sender.
func startUDPEcho(t *testing.T) (host string, port int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return // socket closed
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	a := pc.LocalAddr().(*net.UDPAddr)
	return "127.0.0.1", a.Port
}
