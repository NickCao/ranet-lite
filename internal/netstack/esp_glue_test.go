package netstack

import (
	"crypto/rand"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/esp"
	"github.com/NickCao/ranet-lite/internal/ike"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// TestTCPAcrossMeshWithRealESP exercises the exact seam between this
// package and package esp: an outbound gvisor packet must be handed to
// Peer.sendFn, ESP-sealed with the right next-header, and a decrypted
// inbound packet must be injected back into the stack correctly. It uses
// real AES-GCM ESP encode/decode (not a fake passthrough) on both ends,
// in-process, so it needs no network — UDP transport correctness against a
// real strongSwan responder is proven separately in cmd/esptest.
func TestTCPAcrossMeshWithRealESP(t *testing.T) {
	key := make([]byte, 20) // AES-128-GCM: 16-byte key + 4-byte salt
	rand.Read(key)
	childAtoB := ike.ChildSA{
		EncrID: 20, EncrKeyBits: 128,
		LocalSPI: 0xaaaaaaaa, RemoteSPI: 0xbbbbbbbb,
		InboundKey: key, OutboundKey: key,
	}
	childBtoA := ike.ChildSA{
		EncrID: 20, EncrKeyBits: 128,
		LocalSPI: 0xbbbbbbbb, RemoteSPI: 0xaaaaaaaa,
		InboundKey: key, OutboundKey: key,
	}

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

	addrA := netip.MustParseAddr("10.88.0.1")
	addrB := netip.MustParseAddr("10.88.0.2")
	if err := a.AddLocalAddress(addrA); err != nil {
		t.Fatal(err)
	}
	if err := b.AddLocalAddress(addrB); err != nil {
		t.Fatal(err)
	}

	// inX must be built from X's own ChildSA view (LocalSPI = X's inbound
	// SPI), not the peer's — using the wrong one silently drops every
	// packet on a SPI mismatch instead of failing loudly.
	outA, err := esp.NewOutbound(childAtoB)
	if err != nil {
		t.Fatal(err)
	}
	inA, err := esp.NewInbound(childAtoB)
	if err != nil {
		t.Fatal(err)
	}
	outB, err := esp.NewOutbound(childBtoA)
	if err != nil {
		t.Fatal(err)
	}
	inB, err := esp.NewInbound(childBtoA)
	if err != nil {
		t.Fatal(err)
	}

	peerB := NewPeer("b", func(raw []byte, nh byte) error {
		sealed, err := outA.Seal(raw, nh)
		if err != nil {
			return err
		}
		// "the wire": B decrypts what A sealed and injects it into its stack.
		plain, nh2, err := inB.Open(sealed)
		if err != nil {
			return err
		}
		b.DeliverInbound(plain, nh2)
		return nil
	})
	peerA := NewPeer("a", func(raw []byte, nh byte) error {
		sealed, err := outB.Seal(raw, nh)
		if err != nil {
			return err
		}
		plain, nh2, err := inA.Open(sealed)
		if err != nil {
			return err
		}
		a.DeliverInbound(plain, nh2)
		return nil
	})
	a.Routes.Set(netip.PrefixFrom(addrB, 32), peerB)
	b.Routes.Set(netip.PrefixFrom(addrA, 32), peerA)

	listenAddr := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(addrB.AsSlice()), Port: 9001}
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
		_, err = io.Copy(conn, conn)
		serverErr <- err
	}()

	conn, err := gonet.DialTCP(a.Stack, listenAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	const msg = "hello through real ESP crypto"
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
