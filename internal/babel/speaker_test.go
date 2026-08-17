package babel

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/nickcao/ranet-client/internal/netstack"
)

// wireMeshes connects two Mesh instances with a plain in-memory relay (no
// ESP/crypto — that's validated separately), mirroring
// netstack.TestTCPAcrossMesh. It gives Speaker a real gvisor stack to send
// and receive real UDP packets over, without needing a live network.
func wireMeshes(t *testing.T, addrA, addrB netip.Addr) (a, b *netstack.Mesh) {
	t.Helper()
	a, err := netstack.New(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	b, err = netstack.New(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)

	if err := a.AddLocalAddress(addrA); err != nil {
		t.Fatal(err)
	}
	if err := b.AddLocalAddress(addrB); err != nil {
		t.Fatal(err)
	}

	peerB := netstack.NewPeer("b", func(raw []byte, nh byte) error { b.DeliverInbound(raw, nh); return nil })
	peerA := netstack.NewPeer("a", func(raw []byte, nh byte) error { a.DeliverInbound(raw, nh); return nil })
	a.Routes.Set(netip.PrefixFrom(addrB, 32), peerB)
	b.Routes.Set(netip.PrefixFrom(addrA, 32), peerA)
	return a, b
}

func TestSpeakerLearnsRouteAndRTT(t *testing.T) {
	addrA := netip.MustParseAddr("10.66.0.1")
	addrB := netip.MustParseAddr("10.66.0.2")
	meshA, meshB := wireMeshes(t, addrA, addrB)

	fast := Config{HelloInterval: 50 * time.Millisecond, UpdateInterval: 100 * time.Millisecond}

	speakerA, err := New(fast, meshA)
	if err != nil {
		t.Fatal(err)
	}
	speakerB, err := New(fast, meshB)
	if err != nil {
		t.Fatal(err)
	}

	// A and B are each other's only neighbor, matching the real topology:
	// each netstack.Peer is one ESP tunnel to one peer.
	peerBForA := netstack.NewPeer("b", func(raw []byte, nh byte) error { meshB.DeliverInbound(raw, nh); return nil })
	peerAForB := netstack.NewPeer("a", func(raw []byte, nh byte) error { meshA.DeliverInbound(raw, nh); return nil })
	speakerA.AddPeer("b", addrB, peerBForA)
	speakerB.AddPeer("a", addrA, peerAForB)

	// B originates its own address; A should learn a route to it via babel.
	extra := netip.MustParsePrefix("10.66.9.9/32")
	speakerB.Originate(netip.PrefixFrom(addrB, 32))
	speakerB.Originate(extra)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go speakerA.Run(ctx)
	go speakerB.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := meshA.Routes.Lookup(extra.Addr()); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	peer, ok := meshA.Routes.Lookup(extra.Addr())
	if !ok {
		t.Fatal("A never learned B's originated route within the deadline")
	}
	if peer.ID != "b" {
		t.Fatalf("route installed via peer %q, want \"b\"", peer.ID)
	}

	// RTT should get measured over the local (near-zero-latency) link.
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		speakerA.mu.Lock()
		n := speakerA.neighbors["b"]
		speakerA.mu.Unlock()
		n.mu.Lock()
		have := n.haveRTT
		n.mu.Unlock()
		if have {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("A never measured RTT to B within the deadline")
}

func TestSpeakerRetractsRouteOnNeighborDown(t *testing.T) {
	addrA := netip.MustParseAddr("10.67.0.1")
	addrB := netip.MustParseAddr("10.67.0.2")
	meshA, meshB := wireMeshes(t, addrA, addrB)

	fast := Config{HelloInterval: 30 * time.Millisecond, UpdateInterval: 60 * time.Millisecond}
	speakerA, err := New(fast, meshA)
	if err != nil {
		t.Fatal(err)
	}
	speakerB, err := New(fast, meshB)
	if err != nil {
		t.Fatal(err)
	}

	peerBForA := netstack.NewPeer("b", func(raw []byte, nh byte) error { meshB.DeliverInbound(raw, nh); return nil })
	speakerA.AddPeer("b", addrB, peerBForA)

	extra := netip.MustParsePrefix("10.67.9.9/32")
	speakerB.Originate(extra)
	// B never learns about A (one-directional is enough to prove retraction);
	// give B no peers so it just sends Hello/Update into the void via A's
	// mesh route, which A does receive.
	speakerB.AddPeer("a", addrA, netstack.NewPeer("a", func(raw []byte, nh byte) error { meshA.DeliverInbound(raw, nh); return nil }))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go speakerA.Run(ctx)
	bCtx, bCancel := context.WithCancel(ctx)
	go speakerB.Run(bCtx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := meshA.Routes.Lookup(extra.Addr()); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := meshA.Routes.Lookup(extra.Addr()); !ok {
		t.Fatal("A never learned the route before the down test could proceed")
	}

	bCancel() // B stops sending Hello entirely, simulating a dead link

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := meshA.Routes.Lookup(extra.Addr()); !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("A never retracted the route after B went silent")
}
