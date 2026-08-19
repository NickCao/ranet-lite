package babel

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/netstack"
)

// multicastGroup is the standard Babel link-local multicast address, RFC
// 8966 §4.1. Every ranet peer link is point-to-point (its own ESP tunnel),
// so multicast Hello sent "through" a given peer's tunnel reaches exactly
// that one peer anyway — the same real-world behavior as BIRD's "tunnel"
// interface mode, which still uses this address rather than unicast.
var multicastGroup = netip.MustParseAddr("ff02::1:6")

// neighborState is per-peer Hello/IHU bookkeeping. Every ranet peer is its
// own point-to-point link (a separate ESP tunnel), so there is exactly one
// neighborState per netstack.Peer — no interface-level neighbor discovery.
// addr is learned from the first packet received from this peer, never
// configured — babel here runs purely on multicast, matching the real
// deployment this client targets.
type neighborState struct {
	peer *netstack.Peer

	mu            sync.Mutex
	addr          netip.Addr
	alive         bool
	lastHelloTime time.Time
	helloInterval time.Duration

	// RFC 9616 RTT extension state. theirHello* is what we need to build
	// our own outgoing IHU (echoing their last Hello's transmit time plus
	// our own receive time for it). ourHello* is what we need to validate
	// and use an incoming IHU that's responding to a Hello *we* sent.
	theirHelloTxTS uint32
	theirHelloRxTS uint32
	haveTheirHello bool
	ourHelloTxTS   uint32
	haveOurHello   bool

	reportedCost     uint16 // RxCost the neighbor last told us (its cost of receiving from us)
	haveReportedCost bool
	ihuExpiry        time.Time
	measuredRTT      time.Duration
	haveRTT          bool
	routerID         [8]byte
}

func (n *neighborState) learnAddr(addr netip.Addr) {
	n.mu.Lock()
	n.addr = addr
	n.mu.Unlock()
}

func (n *neighborState) address() netip.Addr {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.addr
}

func deadTimeout(interval time.Duration) time.Duration {
	// Common babel convention (babeld/bird): declare a neighbor dead after
	// missing several Hello intervals, not just one.
	return interval * 7 / 2
}

func (n *neighborState) linkCost() uint16 {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.isAliveLocked() || !n.haveReportedCost || time.Now().After(n.ihuExpiry) {
		return MetricInfinity
	}
	return n.reportedCost
}

func (n *neighborState) isAlive() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.isAliveLocked()
}

func (n *neighborState) isAliveLocked() bool {
	return n.alive && n.helloInterval > 0 && time.Now().Before(n.lastHelloTime.Add(deadTimeout(n.helloInterval)))
}

// shouldDeclareDown reports whether we've heard from this neighbor before
// (helloInterval > 0) but it's no longer alive — distinguishing "never
// heard from" (nothing to declare down) from "went silent".
func (n *neighborState) shouldDeclareDown() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.helloInterval > 0 && !n.isAliveLocked()
}

// Config holds Speaker tuning parameters. Zero values fall back to
// defaults matching a typical tunnel-mesh deployment (20s Hello, RTT
// costing per RFC 9616 up to 1024 over a 1024ms ceiling).
type Config struct {
	RouterID       [8]byte    // zero => generate a random one
	LinkLocalAddr  netip.Addr // zero => generate a random fe80::/64 address
	HelloInterval  time.Duration
	UpdateInterval time.Duration
	Cost           CostParams
}

func randomLinkLocal() netip.Addr {
	var b [16]byte
	b[0], b[1] = 0xfe, 0x80
	rand.Read(b[8:])
	return netip.AddrFrom16(b)
}

func (c *Config) setDefaults() {
	if c.HelloInterval == 0 {
		c.HelloInterval = 20 * time.Second
	}
	if c.UpdateInterval == 0 {
		c.UpdateInterval = 4 * c.HelloInterval
	}
	if c.Cost == (CostParams{}) {
		c.Cost = DefaultCostParams()
	}
	if c.RouterID == ([8]byte{}) {
		rand.Read(c.RouterID[:])
	}
	if !c.LinkLocalAddr.IsValid() {
		c.LinkLocalAddr = randomLinkLocal()
	}
}

// Speaker is a minimal Babel router: it maintains Hello/IHU state with
// each configured peer, exchanges Update TLVs, and keeps
// internal/netstack.RouteTable in sync with the best known route per
// (source, destination) key — including genuine source-specific (SADR)
// routes, installed directly rather than approximated, since the mesh's
// TUN device sees every packet's real source and destination address
// itself. It does not use the mesh's TUN device for its own wire I/O —
// each peer is addressed directly via its netstack.Peer send function and
// fed received packets directly by the caller's ESP receive loop (see
// Receive) — only the routes it *learns* go into the shared RouteTable.
type Speaker struct {
	cfg  Config
	mesh *netstack.Mesh

	mu        sync.Mutex
	neighbors map[string]*neighborState // keyed by netstack.Peer.ID
	originate map[netip.Prefix]struct{}
	routes    *routeTable

	changed chan struct{}
}

// PeerHandle owns one exact Speaker registration. Closing a stale handle does
// not disturb a newer session that reused the same peer ID.
type PeerHandle struct {
	speaker *Speaker
	state   *neighborState
	once    sync.Once
}

func (h *PeerHandle) Close() {
	if h == nil {
		return
	}
	h.once.Do(func() { h.speaker.removePeer(h.state) })
}

func New(cfg Config, mesh *netstack.Mesh) (*Speaker, error) {
	cfg.setDefaults()
	return &Speaker{
		cfg: cfg, mesh: mesh,
		neighbors: map[string]*neighborState{},
		originate: map[netip.Prefix]struct{}{},
		routes:    newRouteTable(),
		changed:   make(chan struct{}, 1),
	}, nil
}

// AddPeer registers a Babel neighbor over the given netstack.Peer (its
// ESP-backed tunnel). Its address is learned automatically from the first
// packet it sends — nothing needs to be configured up front.
func (s *Speaker) AddPeer(peer *netstack.Peer) *PeerHandle {
	n := &neighborState{peer: peer}
	s.mu.Lock()
	old := s.neighbors[peer.ID]
	s.neighbors[peer.ID] = n
	s.mu.Unlock()
	if old != nil {
		s.removePeer(old)
	}
	return &PeerHandle{speaker: s, state: n}
}

func (s *Speaker) removePeer(n *neighborState) {
	s.mu.Lock()
	if s.neighbors[n.peer.ID] == n {
		delete(s.neighbors, n.peer.ID)
	}
	s.mu.Unlock()
	for _, key := range s.routes.expireNeighbor(n) {
		s.installRoute(key, s.routes.selectedFor(key))
	}
	s.mesh.Routes.RemovePeer(n.peer)
	s.triggerUpdate()
}

// Receive processes a decrypted packet that arrived via peer's ESP tunnel.
// It returns true if the packet was Babel control traffic (and so has been
// fully handled); the caller should deliver anything else (false) to the
// mesh's netstack as usual.
func (s *Speaker) Receive(peer *netstack.Peer, raw []byte) bool {
	src, payload, err := parsePacket(raw, s.cfg.LinkLocalAddr)
	if err != nil {
		return false
	}
	s.mu.Lock()
	n := s.neighbors[peer.ID]
	s.mu.Unlock()
	if n == nil {
		return false
	}
	n.learnAddr(src)
	s.handlePacket(n, payload)
	return true
}

// Originate announces prefix as reachable via this node, with a fixed
// low (directly-connected) cost.
func (s *Speaker) Originate(prefix netip.Prefix) {
	s.mu.Lock()
	s.originate[prefix] = struct{}{}
	s.mu.Unlock()
	s.triggerUpdate()
}

func (s *Speaker) triggerUpdate() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// Run services the Hello/IHU/Update timers until ctx is canceled. Unlike
// the timers, receiving has no loop of its own here — see Receive, which
// the caller invokes directly from each peer's ESP receive loop.
func (s *Speaker) Run(ctx context.Context) error {
	go s.helloLoop(ctx)
	go s.updateLoop(ctx)
	<-ctx.Done()
	return ctx.Err()
}

func (s *Speaker) send(n *neighborState, tlvs []RawTLV) {
	s.sendTo(n, multicastGroup, tlvs)
}

func (s *Speaker) sendTo(n *neighborState, destination netip.Addr, tlvs []RawTLV) {
	pkt := buildPacket(s.cfg.LinkLocalAddr, destination, EncodePacket(tlvs))
	if err := n.peer.SendRaw(pkt, esp.NextHeaderIPv6); err != nil {
		slog.Warn("babel send failed", "peer", n.peer.ID, "err", err)
	} else {
		slog.Debug("babel sent packet", "peer", n.peer.ID, "tlvs", len(tlvs), "bytes", len(pkt))
	}
}

// --- sending: Hello/IHU ---

func (s *Speaker) helloLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.HelloInterval)
	defer ticker.Stop()
	var seqno uint16
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			seqno++
			s.mu.Lock()
			neighbors := make([]*neighborState, 0, len(s.neighbors))
			for _, n := range s.neighbors {
				neighbors = append(neighbors, n)
			}
			s.mu.Unlock()
			for _, n := range neighbors {
				s.sendHelloIHU(n, seqno)
				if n.shouldDeclareDown() {
					s.neighborDown(n)
				}
			}
		}
	}
}

func (s *Speaker) sendHelloIHU(n *neighborState, seqno uint16) {
	centis := uint16(s.cfg.HelloInterval / (10 * time.Millisecond))
	txTS := nowMicros()
	tlvs := []RawTLV{EncodeHello(Hello{Seqno: seqno, Interval: centis, TxTS: txTS, HasTS: true})}

	n.mu.Lock()
	n.ourHelloTxTS, n.haveOurHello = txTS, true
	haveTheirHello := n.haveTheirHello
	theirTxTS, theirRxTS := n.theirHelloTxTS, n.theirHelloRxTS
	n.mu.Unlock()

	rxCost := s.cfg.Cost.RxCost
	if n.isAlive() {
		n.mu.Lock()
		rtt, haveRTT := n.measuredRTT, n.haveRTT
		n.mu.Unlock()
		rxCost = s.cfg.Cost.Cost(rtt, haveRTT)
	}
	ihu := IHU{RxCost: rxCost, Interval: centis}
	if haveTheirHello {
		ihu.OriginTS, ihu.ReceiveTS, ihu.HasTS = theirTxTS, theirRxTS, true
	}
	tlvs = append(tlvs, EncodeIHU(ihu))
	s.send(n, tlvs)
}

// --- sending: Update ---

func (s *Speaker) updateLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.UpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepExpired()
			s.flushUpdates()
		case <-s.changed:
			s.flushUpdates()
		}
	}
}

// installRoute pushes a route selection decision into the shared
// netstack.RouteTable and logs it — the single choke point every route
// change (fresh Update, periodic expiry sweep, neighbor going down) goes
// through, so `grep 'babel: route'` on the log is a full account of what
// this node has ever installed or retracted.
func (s *Speaker) installRoute(key routeKey, sel *routeInfo) {
	desc := key.dest.String()
	if key.source.IsValid() {
		desc = fmt.Sprintf("%s from %s", key.dest, key.source)
	}
	if sel != nil && sel.reachable() {
		s.mesh.Routes.Set(key.source, key.dest, sel.neighbor.peer)
		slog.Info("babel route installed", "route", desc, "peer", sel.neighbor.peer.ID, "metric", sel.cost)
	} else {
		s.mesh.Routes.Remove(key.source, key.dest)
		slog.Info("babel route retracted", "route", desc)
	}
}

// sweepExpired re-checks every selected route's TTL. update() only
// re-evaluates reachability when a fresh Update for that exact prefix
// arrives; without this periodic sweep, a neighbor that stops sending
// Updates entirely (as opposed to just missing Hellos) would never be
// noticed and its routes would linger forever.
func (s *Speaker) sweepExpired() {
	s.routes.sweepExpired(s.installRoute)
}

func (s *Speaker) flushUpdates() {
	s.mu.Lock()
	neighbors := make([]*neighborState, 0, len(s.neighbors))
	for _, n := range s.neighbors {
		neighbors = append(neighbors, n)
	}
	originate := make([]netip.Prefix, 0, len(s.originate))
	for p := range s.originate {
		originate = append(originate, p)
	}
	s.mu.Unlock()

	centis := uint16(s.cfg.UpdateInterval / (10 * time.Millisecond))

	// This client is always a stub/leaf, never transit: it announces only
	// what it originates itself. Redistributing routes learned from one
	// peer to another would claim routing capability the data plane
	// doesn't back up — the gvisor stack here has no IP forwarding
	// enabled, so a peer trying to route through this node would just see
	// its packets dropped.
	if len(originate) == 0 {
		return
	}
	for _, n := range neighbors {
		var tlvs []RawTLV
		for _, p := range originate {
			tlvs = append(tlvs, EncodeRouterID(s.cfg.RouterID))
			tlvs = append(tlvs, EncodeUpdate(Update{
				AE: aeFor(p), Plen: p.Bits(), Interval: centis, Seqno: 1, Metric: 0, Prefix: net.IP(p.Addr().AsSlice()),
			}))
		}
		s.send(n, tlvs)
	}
}

func aeFor(p netip.Prefix) uint8 {
	if p.Addr().Is4() {
		return AEIPv4
	}
	return AEIPv6
}

// --- receiving ---

func (s *Speaker) handlePacket(n *neighborState, raw []byte) {
	tlvs, err := DecodePacket(raw)
	if err != nil {
		slog.Warn("babel bad packet", "err", err)
		return
	}
	prefixDec := &PrefixDecoder{}
	var curRouterID [8]byte
	var haveRouterID bool
	var freshHelloTxTS uint32
	var haveFreshHello bool

	for _, t := range tlvs {
		switch t.Type {
		case TLVHello:
			h, err := DecodeHello(t.Body)
			if err != nil {
				continue
			}
			recvTS := nowMicros()
			n.mu.Lock()
			if !n.alive {
				slog.Info("babel neighbor up", "peer", n.peer.ID)
			}
			n.alive = true
			n.lastHelloTime = time.Now()
			n.helloInterval = time.Duration(h.Interval) * 10 * time.Millisecond
			if h.HasTS {
				n.theirHelloTxTS, n.theirHelloRxTS, n.haveTheirHello = h.TxTS, recvTS, true
				freshHelloTxTS, haveFreshHello = h.TxTS, true
			}
			n.mu.Unlock()
			s.routes.recomputeNeighbor(n, s.installRoute)

		case TLVIHU:
			ihu, _, err := DecodeIHU(t.Body)
			if err != nil {
				continue
			}
			now := nowMicros()
			n.mu.Lock()
			n.reportedCost = ihu.RxCost
			n.haveReportedCost = true
			n.ihuExpiry = time.Now().Add(time.Duration(ihu.Interval) * 10 * time.Millisecond * 7 / 2)
			// RFC 9616 §3: this IHU only yields an RTT sample if it
			// answers a Hello we actually sent (OriginTS matches) *and*
			// the same packet also carries a fresh Hello from them — that
			// second timestamp is what lets us subtract their processing
			// delay back out, rather than counting it as network latency.
			if ihu.HasTS && haveFreshHello && n.haveOurHello && ihu.OriginTS == n.ourHelloTxTS {
				rtt := microDelta(now, n.ourHelloTxTS) - microDelta(freshHelloTxTS, ihu.ReceiveTS)
				if rtt > 0 {
					n.measuredRTT, n.haveRTT = rtt, true
				}
			}
			n.mu.Unlock()
			s.routes.recomputeNeighbor(n, s.installRoute)

		case TLVRouterID:
			id, err := DecodeRouterID(t.Body)
			if err == nil {
				curRouterID = id
				haveRouterID = true
			}

		case TLVUpdate:
			u, err := prefixDec.Decode(t.Body)
			if err != nil {
				slog.Warn("babel bad update", "err", err)
				continue
			}
			if u.Ignore {
				// Carries some other mandatory sub-TLV we don't recognize
				// at all, or a malformed Source Prefix. Per RFC 8966
				// §4.4 the whole TLV is ignored; the prefix-compression
				// state above was still updated.
				continue
			}
			if u.AE == AEWildcard {
				for _, key := range s.routes.expireNeighbor(n) {
					s.installRoute(key, s.routes.selectedFor(key))
				}
				s.triggerUpdate()
				continue
			}
			if !haveRouterID && u.Metric != MetricInfinity {
				continue
			}
			addr, ok := netip.AddrFromSlice(u.Prefix)
			if !ok {
				continue
			}
			prefix := netip.PrefixFrom(addr.Unmap(), u.Plen).Masked()
			if curRouterID == s.cfg.RouterID {
				// This route is ours. Split horizon (RFC 8966 §3.7.4)
				// only ever suppresses re-advertising back out the *one*
				// interface a route was learned on, so it does nothing
				// against our own prefix looping back via a *different*
				// peer after crossing other nodes in an actual mesh — the
				// router-id is the general, mesh-wide-safe check.
				// Accepting it would redirect our own traffic out through
				// that peer.
				continue
			}
			// u.SourcePrefix is the zero value for an ordinary Update,
			// which is exactly routeKey's "any source" sentinel — a
			// genuine source-specific (SADR) route is tracked completely
			// independently from any ordinary route to the same
			// destination, and the mesh's route table resolves which one
			// applies per-packet using each packet's real source address.
			key := routeKey{source: u.SourcePrefix, dest: prefix}
			ttl := time.Duration(u.Interval) * 10 * time.Millisecond * 7 / 2
			changed, sel := s.routes.update(n, key, curRouterID, u.Seqno, u.Metric, ttl)
			if changed {
				s.installRoute(key, sel)
				s.triggerUpdate()
			}

		case TLVAckReq:
			nonce, err := DecodeAckReq(t.Body)
			if destination := n.address(); err == nil && destination.IsValid() {
				s.sendTo(n, destination, []RawTLV{EncodeAck(nonce)})
			}
		}
	}
}

func (s *Speaker) neighborDown(n *neighborState) {
	slog.Info("babel neighbor down", "peer", n.peer.ID)
	n.mu.Lock()
	n.alive = false
	n.haveReportedCost = false
	n.mu.Unlock()
	for _, key := range s.routes.expireNeighbor(n) {
		s.installRoute(key, s.routes.selectedFor(key))
	}
	s.mesh.Routes.RemovePeer(n.peer)
	s.triggerUpdate()
}
