package babel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
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
	// Babel only uses Mesh.Routes. Avoid creating a privileged TUN device for
	// protocol tests that never inject non-Babel data into the mesh.
	meshA = &netstack.Mesh{Routes: netstack.NewRouteTable()}
	meshB = &netstack.Mesh{Routes: netstack.NewRouteTable()}

	speakerA, err := New(cfg, meshA)
	if err != nil {
		t.Fatal(err)
	}
	speakerB, err = New(cfg, meshB)
	if err != nil {
		t.Fatal(err)
	}

	// Crypto and transport are tested separately; this pair only exercises
	// Babel and mesh delivery.
	noopEncrypt := func(raw []byte, nh byte) ([]byte, error) { return raw, nil }

	var peerAForB, peerBForA *netstack.Peer
	peerBForA = netstack.NewPeer("b", noopEncrypt, func(raw []byte) error {
		if !speakerB.Receive(peerAForB, raw) {
			meshB.DeliverInbound(raw)
		}
		return nil
	})
	peerAForB = netstack.NewPeer("a", noopEncrypt, func(raw []byte) error {
		if !speakerA.Receive(peerBForA, raw) {
			meshA.DeliverInbound(raw)
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

	// extra is an ordinary (any-source) route, so the source address
	// passed to Lookup is irrelevant — any placeholder works.
	dummySrc := netip.MustParseAddr("192.0.2.1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go speakerA.Run(ctx)
	go speakerB.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := meshA.Routes.Lookup(dummySrc, extra.Addr()); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	peer, ok := meshA.Routes.Lookup(dummySrc, extra.Addr())
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
	n.mu.Lock()
	n.alive = true
	n.lastHelloTime = time.Now()
	n.helloInterval = time.Minute
	n.haveReportedCost = true
	n.reportedCost = 32
	n.ihuExpiry = time.Now().Add(time.Minute)
	n.mu.Unlock()
	pkt := buildPacket(netip.MustParseAddr("fe80::b"), multicastGroup, EncodePacket([]RawTLV{
		EncodeRouterID(speakerA.cfg.RouterID), // as if reflected back via another mesh node
		EncodeUpdate(Update{AE: AEIPv6, Plen: mine.Bits(), Seqno: 1, Metric: 32, Prefix: net.IP(mine.Addr().AsSlice())}),
	}))
	speakerA.handlePacket(n, pkt[ipv6HeaderLen+udpHeaderLen:])

	if peer, ok := meshA.Routes.Lookup(netip.MustParseAddr("192.0.2.1"), mine.Addr()); ok {
		t.Fatalf("A installed a learned route for its own originated prefix via peer %q", peer.ID)
	}
}

// sourceSpecificUpdateTLV hand-builds an Update TLV with a trailing Source
// Prefix sub-TLV (draft-ietf-babel-source-specific §7.1) — EncodeUpdate
// doesn't support this (we never originate source-specific routes), so
// tests exercising receive-side handling build the bytes directly, same
// as tlv_test.go's TestUpdateWithSourcePrefix.
func sourceSpecificUpdateTLV(dest netip.Prefix, source netip.Prefix, metric uint16) RawTLV {
	ae := aeFor(dest)
	destBytes := dest.Addr().AsSlice()
	if ae == AEIPv4 {
		b := dest.Addr().As4()
		destBytes = b[:]
	}
	srcBytes := source.Addr().AsSlice()
	if aeFor(source) == AEIPv4 {
		b := source.Addr().As4()
		srcBytes = b[:]
	}
	srcBytes = srcBytes[:prefixByteLen(source.Bits())]

	body := make([]byte, 0, 32)
	body = append(body, ae, 0, byte(dest.Bits()), 0)   // AE, Flags, Plen, Omitted
	body = append(body, 0, 200)                        // Interval: 200 centiseconds, long enough to outlive the test
	body = append(body, 0, 1)                          // Seqno
	body = append(body, byte(metric>>8), byte(metric)) // Metric
	body = append(body, destBytes[:prefixByteLen(dest.Bits())]...)
	body = append(body, SubTLVSourcePrefix, byte(1+len(srcBytes)), byte(source.Bits()))
	body = append(body, srcBytes...)
	return RawTLV{Type: TLVUpdate, Body: body}
}

func makeNeighborReachable(n *neighborState) {
	n.mu.Lock()
	n.alive = true
	n.lastHelloTime = time.Now()
	n.helloInterval = time.Minute
	n.haveReportedCost = true
	n.reportedCost = 32
	n.ihuExpiry = time.Now().Add(time.Minute)
	n.mu.Unlock()
}

// TestSpeakerSADR covers genuine source-specific (SADR) route handling:
// a Source Prefix sub-TLV is installed as a real (source, destination)
// entry in the mesh's route table, not approximated by checking whether
// it happens to cover some fixed local address. Two source-specific
// routes to the same destination, from different peers/prefixes, must
// coexist independently and only resolve for lookups whose source
// address actually falls within their respective source prefix.
func TestSpeakerSADR(t *testing.T) {
	_, _, speakerA, _ := wireSpeakerPair(t, Config{})

	n := speakerA.neighbors["b"]
	if n == nil {
		t.Fatal("peer \"b\" not registered")
	}
	makeNeighborReachable(n)

	dest := netip.MustParsePrefix("10.77.0.0/24")
	covering := netip.MustParsePrefix("10.66.0.0/16")
	other := netip.MustParsePrefix("10.99.0.0/16")

	pkt := buildPacket(netip.MustParseAddr("fe80::b"), multicastGroup, EncodePacket([]RawTLV{
		EncodeRouterID([8]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		sourceSpecificUpdateTLV(dest, other, 64),
	}))
	speakerA.handlePacket(n, pkt[ipv6HeaderLen+udpHeaderLen:])

	// A source inside `other`'s prefix must resolve via the
	// source-specific route just installed.
	if _, ok := speakerA.mesh.Routes.Lookup(netip.MustParseAddr("10.99.1.1"), dest.Addr()); !ok {
		t.Fatal("did not install the source-specific route for a source within its prefix")
	}
	// A source outside `other`'s prefix, and with no any-source fallback
	// route to dest, must not match at all.
	if _, ok := speakerA.mesh.Routes.Lookup(netip.MustParseAddr("10.66.1.1"), dest.Addr()); ok {
		t.Fatal("a source-specific route matched a source outside its prefix")
	}

	// A second, independent source-specific route to the *same*
	// destination must coexist rather than replacing the first.
	pkt = buildPacket(netip.MustParseAddr("fe80::b"), multicastGroup, EncodePacket([]RawTLV{
		EncodeRouterID([8]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		sourceSpecificUpdateTLV(dest, covering, 64),
	}))
	speakerA.handlePacket(n, pkt[ipv6HeaderLen+udpHeaderLen:])

	if _, ok := speakerA.mesh.Routes.Lookup(netip.MustParseAddr("10.66.1.1"), dest.Addr()); !ok {
		t.Fatal("did not install the second source-specific route")
	}
	if _, ok := speakerA.mesh.Routes.Lookup(netip.MustParseAddr("10.99.1.1"), dest.Addr()); !ok {
		t.Fatal("installing a second source-specific route disturbed the first")
	}
}

func TestSpeakerRetractsRouteOnNeighborDown(t *testing.T) {
	fast := Config{HelloInterval: 30 * time.Millisecond, UpdateInterval: 60 * time.Millisecond}
	meshA, _, speakerA, speakerB := wireSpeakerPair(t, fast)

	extra := netip.MustParsePrefix("10.67.9.9/32")
	speakerB.Originate(extra)
	dummySrc := netip.MustParseAddr("192.0.2.1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go speakerA.Run(ctx)
	bCtx, bCancel := context.WithCancel(ctx)
	go speakerB.Run(bCtx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := meshA.Routes.Lookup(dummySrc, extra.Addr()); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := meshA.Routes.Lookup(dummySrc, extra.Addr()); !ok {
		t.Fatal("A never learned the route before the down test could proceed")
	}

	bCancel() // B stops sending Hello entirely, simulating a dead link

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := meshA.Routes.Lookup(dummySrc, extra.Addr()); !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("A never retracted the route after B went silent")
}

func TestPeerHandleRemovesExactNeighborAndRoutes(t *testing.T) {
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := New(Config{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	peer := netstack.NewPeer("peer", nil, nil)
	handle := speaker.AddPeer(peer)
	n := speaker.neighbors[peer.ID]
	dest := netip.MustParsePrefix("10.88.0.0/16")
	key := routeKey{dest: dest}
	_, selected := speaker.routes.update(n, key, [8]byte{1}, 1, 1, time.Minute)
	speaker.installRoute(key, selected)

	handle.Close()
	handle.Close()
	if speaker.neighbors[peer.ID] != nil {
		t.Fatal("closed peer remains registered")
	}
	if _, ok := mesh.Routes.Lookup(netip.MustParseAddr("192.0.2.1"), dest.Addr()); ok {
		t.Fatal("closed peer route remains installed")
	}

	newPeer := netstack.NewPeer("peer", nil, nil)
	newHandle := speaker.AddPeer(newPeer)
	defer newHandle.Close()
	handle.Close()
	if speaker.neighbors[peer.ID] == nil {
		t.Fatal("stale handle removed replacement peer")
	}
}
