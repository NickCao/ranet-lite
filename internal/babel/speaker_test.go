package babel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nickcao/ranet-client/internal/netstack"
)

// wireSpeakerPair connects two Speakers via a plain in-memory relay (no
// ESP/crypto — that's validated separately) that threads peer identity
// correctly: each side's netstack.Peer represents "the other side" from
// its own point of view, exactly as in the real client where each peer
// object corresponds to one ESP session. Non-Babel traffic (Receive
// returns false) falls through to the mesh, mirroring how a real
// per-peer ESP receive loop would dispatch between babel and app traffic.
func wireSpeakerPair(t *testing.T, cfg Config) (meshA, meshB *netstack.Mesh, speakerA, speakerB *Speaker) {
	t.Helper()
	var err error
	meshA, err = netstack.New(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(meshA.Close)
	meshB, err = netstack.New(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(meshB.Close)

	speakerA, err = New(cfg, meshA)
	if err != nil {
		t.Fatal(err)
	}
	speakerB, err = New(cfg, meshB)
	if err != nil {
		t.Fatal(err)
	}

	var peerAForB, peerBForA *netstack.Peer
	peerBForA = netstack.NewPeer("b", func(raw []byte, nh byte) error {
		if !speakerB.Receive(peerAForB, raw) {
			meshB.DeliverInbound(raw, nh)
		}
		return nil
	})
	peerAForB = netstack.NewPeer("a", func(raw []byte, nh byte) error {
		if !speakerA.Receive(peerBForA, raw) {
			meshA.DeliverInbound(raw, nh)
		}
		return nil
	})
	speakerA.AddPeer(peerBForA)
	speakerB.AddPeer(peerAForB)
	return meshA, meshB, speakerA, speakerB
}

func TestSpeakerLearnsRouteAndRTT(t *testing.T) {
	fast := Config{HelloInterval: 50 * time.Millisecond, UpdateInterval: 100 * time.Millisecond}
	meshA, _, speakerA, speakerB := wireSpeakerPair(t, fast)

	extra := netip.MustParsePrefix("10.66.9.9/32")
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

// TestSpeakerIgnoresEchoedOwnPrefix guards against a real bug found during
// BIRD interop: a peer that doesn't implement split horizon (BIRD doesn't,
// at least over "type tunnel") re-sends our own originated prefix back to
// us. Split horizon (RFC 8966 §3.7.4) only ever suppresses re-advertising
// back out the *one* interface a route was learned on — it says nothing
// about our own prefix looping back via a *different* peer after crossing
// other nodes in an actual mesh, so the real guard has to be router-id
// based, not "did this arrive on the peer I sent it to". This injects a
// non-compliant Update tagged with our own router-id, exactly what BIRD
// was observed sending on the wire.
func TestSpeakerIgnoresEchoedOwnPrefix(t *testing.T) {
	meshA, _, speakerA, _ := wireSpeakerPair(t, Config{})

	mine := netip.MustParsePrefix("fd00:68::9/128")
	speakerA.Originate(mine)

	n := speakerA.neighbors["b"]
	if n == nil {
		t.Fatal("peer \"b\" not registered")
	}
	pkt := buildPacket(netip.MustParseAddr("fe80::b"), multicastGroup, EncodePacket([]RawTLV{
		EncodeRouterID(speakerA.cfg.RouterID), // as if reflected back via another mesh node
		EncodeUpdate(Update{AE: AEIPv6, Plen: mine.Bits(), Seqno: 1, Metric: 32, Prefix: net.IP(mine.Addr().AsSlice())}),
	}))
	speakerA.handlePacket(n, pkt[ipv6HeaderLen+udpHeaderLen:])

	if peer, ok := meshA.Routes.Lookup(mine.Addr()); ok {
		t.Fatalf("A installed a learned route for its own originated prefix via peer %q", peer.ID)
	}
}

func TestSpeakerRetractsRouteOnNeighborDown(t *testing.T) {
	fast := Config{HelloInterval: 30 * time.Millisecond, UpdateInterval: 60 * time.Millisecond}
	meshA, _, speakerA, speakerB := wireSpeakerPair(t, fast)

	extra := netip.MustParsePrefix("10.67.9.9/32")
	speakerB.Originate(extra)

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
