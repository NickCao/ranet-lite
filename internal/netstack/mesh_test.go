package netstack

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// TestTCPAcrossMesh proves the gvisor wiring itself: two independent Mesh
// stacks, connected only by a plain in-memory relay (no ESP, no crypto —
// that's validated separately in package esp), can complete a real TCP
// handshake and exchange data end to end through DeliverInbound/RouteTable.
func TestTCPAcrossMesh(t *testing.T) {
	a, err := New(0)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	addrA := netip.MustParseAddr("10.77.0.1")
	addrB := netip.MustParseAddr("10.77.0.2")
	if err := a.AddLocalAddress(addrA); err != nil {
		t.Fatal(err)
	}
	if err := b.AddLocalAddress(addrB); err != nil {
		t.Fatal(err)
	}

	peerB := NewPeer("b", func(raw []byte, nh byte) error { b.DeliverInbound(raw, nh); return nil })
	peerA := NewPeer("a", func(raw []byte, nh byte) error { a.DeliverInbound(raw, nh); return nil })
	a.Routes.Set(netip.PrefixFrom(addrB, 32), peerB)
	b.Routes.Set(netip.PrefixFrom(addrA, 32), peerA)

	listenAddr := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(addrB.AsSlice()), Port: 9000}
	ln, err := gonet.ListenTCP(b.Stack, listenAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_, err = io.Copy(conn, conn) // echo whatever the client sends
		serverErr <- err
	}()

	conn, err := gonet.DialTCP(a.Stack, listenAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	const msg = "hello across the mesh"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.CloseWrite()

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}

	select {
	case err := <-serverErr:
		if err != nil && err != io.EOF {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never finished")
	}
}

// TestNoRouteDrops confirms packets to an unroutable destination are simply
// dropped (mirroring normal IP behavior for this minimal client — no ICMP
// unreachable generation) rather than blocking or panicking.
func TestNoRouteDrops(t *testing.T) {
	a, err := New(0)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.AddLocalAddress(netip.MustParseAddr("10.77.0.1")); err != nil {
		t.Fatal(err)
	}
	dst := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(netip.MustParseAddr("10.77.0.9").AsSlice()), Port: 9000}
	// Packets to an unrouted destination are silently dropped by sendOut
	// (no ICMP unreachable in this minimal client), so the connect attempt
	// just never completes — bound with a short deadline rather than
	// expecting a synchronous error.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = gonet.DialContextTCP(ctx, a.Stack, dst, ipv4.ProtocolNumber)
	if err == nil {
		t.Fatal("expected dial to an unrouted address to fail")
	}
}
