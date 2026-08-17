package babel

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/nickcao/ranet-client/internal/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// neighborState is per-peer Hello/IHU bookkeeping. Every ranet peer is its
// own point-to-point link (a separate ESP tunnel), so there is exactly one
// neighborState per netstack.Peer — no interface-level neighbor discovery.
type neighborState struct {
	id   string
	peer *netstack.Peer
	addr netip.Addr

	mu               sync.Mutex
	alive            bool
	lastHelloTime    time.Time
	helloInterval    time.Duration
	lastHelloTSTx    uint32
	haveLastHelloTS  bool
	reportedCost     uint16 // RxCost the neighbor last told us (its cost of receiving from us)
	haveReportedCost bool
	ihuExpiry        time.Time
	measuredRTT      time.Duration
	haveRTT          bool
	routerID         [8]byte
}

func deadTimeout(interval time.Duration) time.Duration {
	// Common babel convention (babeld/bird): declare a neighbor dead after
	// missing several Hello intervals, not just one.
	return interval * 7 / 2
}

func (n *neighborState) linkCost() uint16 {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.haveReportedCost || time.Now().After(n.ihuExpiry) {
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
	RouterID       [8]byte // zero => generate a random one
	HelloInterval  time.Duration
	UpdateInterval time.Duration
	Cost           CostParams
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
}

// Speaker is a minimal Babel router: it maintains Hello/IHU state with
// each configured peer, exchanges Update TLVs, and keeps
// internal/netstack.RouteTable in sync with the best known route per
// prefix. Babel control traffic itself flows as ordinary UDP through the
// mesh (see New) — it's just another application on top of the same ESP
// tunnels, no special-casing needed anywhere else in the stack.
type Speaker struct {
	cfg  Config
	mesh *netstack.Mesh
	udp4 *gonet.UDPConn
	udp6 *gonet.UDPConn

	mu        sync.Mutex
	neighbors map[string]*neighborState
	byAddr    map[netip.Addr]*neighborState
	originate map[netip.Prefix]struct{}
	routes    *routeTable

	changed chan struct{}
}

// newV6OnlyUDP builds a UDP listener bound to [::]:Port with IPV6_V6ONLY
// set, so it doesn't collide with the separate IPv4 wildcard listener on
// the same port (gonet.DialUDP offers no way to set socket options before
// bind, hence the lower-level endpoint construction here).
func newV6OnlyUDP(s *stack.Stack) (*gonet.UDPConn, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if err != nil {
		return nil, fmt.Errorf("new endpoint: %s", err)
	}
	ep.SocketOptions().SetV6Only(true)
	if err := ep.Bind(tcpip.FullAddress{Port: Port}); err != nil {
		ep.Close()
		return nil, fmt.Errorf("bind: %s", err)
	}
	return gonet.NewUDPConn(&wq, ep), nil
}

func New(cfg Config, mesh *netstack.Mesh) (*Speaker, error) {
	cfg.setDefaults()

	udp4, err := gonet.DialUDP(mesh.Stack, &tcpip.FullAddress{Port: Port}, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("babel: listen udp4: %w", err)
	}
	// The v4 and v6 listeners share one stack-wide UDP port space, so the
	// v6 socket must opt out of dual-stack (IPV6_V6ONLY) before binding,
	// same as on a real dual-stack OS — otherwise binding port 6696 twice
	// (once per gonet.DialUDP call above) collides.
	udp6, err := newV6OnlyUDP(mesh.Stack)
	if err != nil {
		udp4.Close()
		return nil, fmt.Errorf("babel: listen udp6: %w", err)
	}

	return &Speaker{
		cfg: cfg, mesh: mesh, udp4: udp4, udp6: udp6,
		neighbors: map[string]*neighborState{},
		byAddr:    map[netip.Addr]*neighborState{},
		originate: map[netip.Prefix]struct{}{},
		routes:    newRouteTable(),
		changed:   make(chan struct{}, 1),
	}, nil
}

// AddPeer registers a Babel neighbor reachable at addr (the peer's inner
// mesh address) via the given netstack.Peer (its ESP-backed route).
func (s *Speaker) AddPeer(id string, addr netip.Addr, peer *netstack.Peer) {
	n := &neighborState{id: id, peer: peer, addr: addr}
	s.mu.Lock()
	s.neighbors[id] = n
	s.byAddr[addr] = n
	s.mu.Unlock()
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

// Run services Hello/IHU/Update timers and the receive loop until ctx is
// canceled.
func (s *Speaker) Run(ctx context.Context) error {
	go s.recvLoop(ctx, s.udp4)
	go s.recvLoop(ctx, s.udp6)
	go s.helloLoop(ctx)
	go s.updateLoop(ctx)
	<-ctx.Done()
	s.udp4.Close()
	s.udp6.Close()
	return ctx.Err()
}

func (s *Speaker) conn(addr netip.Addr) *gonet.UDPConn {
	if addr.Is4() {
		return s.udp4
	}
	return s.udp6
}

func fullAddr(addr netip.Addr) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IP(addr.AsSlice()), Port: Port}
}

func (s *Speaker) send(n *neighborState, tlvs []RawTLV) {
	pkt := EncodePacket(tlvs)
	if _, err := s.conn(n.addr).WriteTo(pkt, fullAddr(n.addr)); err != nil {
		log.Printf("babel: send to %s: %v", n.addr, err)
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
	tlvs := []RawTLV{EncodeHello(Hello{Seqno: seqno, Interval: centis, TSTx: nowMillis(), HasTS: true})}

	n.mu.Lock()
	haveTS := n.haveLastHelloTS
	origin := n.lastHelloTSTx
	n.mu.Unlock()

	rxCost := s.cfg.Cost.RxCost
	if n.isAlive() {
		n.mu.Lock()
		rtt, haveRTT := n.measuredRTT, n.haveRTT
		n.mu.Unlock()
		rxCost = s.cfg.Cost.Cost(rtt, haveRTT)
	}
	ihu := IHU{RxCost: rxCost, Interval: centis}
	if haveTS {
		ihu.TSTx, ihu.TSOrigin, ihu.HasTS = nowMillis(), origin, true
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

// sweepExpired re-checks every selected route's TTL. update() only
// re-evaluates reachability when a fresh Update for that exact prefix
// arrives; without this periodic sweep, a neighbor that stops sending
// Updates entirely (as opposed to just missing Hellos) would never be
// noticed and its routes would linger forever.
func (s *Speaker) sweepExpired() {
	s.routes.sweepExpired(func(prefix netip.Prefix, sel *routeInfo) {
		if sel != nil && sel.reachable() {
			s.mesh.Routes.Set(prefix, sel.neighbor.peer)
		} else {
			s.mesh.Routes.Remove(prefix)
		}
	})
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

	for _, n := range neighbors {
		var tlvs []RawTLV
		for _, p := range originate {
			tlvs = append(tlvs, EncodeRouterID(s.cfg.RouterID))
			tlvs = append(tlvs, EncodeUpdate(Update{
				AE: aeFor(p), Plen: p.Bits(), Interval: centis, Seqno: 1, Metric: 0, Prefix: net.IP(p.Addr().AsSlice()),
			}))
		}
		for prefix, sel := range s.routes.snapshotSelected() {
			if sel.neighbor == n {
				continue // split horizon: don't advertise a route back to its source
			}
			tlvs = append(tlvs, EncodeRouterID(sel.routerID))
			tlvs = append(tlvs, EncodeUpdate(Update{
				AE: aeFor(prefix), Plen: prefix.Bits(), Interval: centis,
				Seqno: sel.seqno, Metric: sel.rxMetric, Prefix: net.IP(prefix.Addr().AsSlice()),
			}))
		}
		if len(tlvs) > 0 {
			s.send(n, tlvs)
		}
	}
}

func aeFor(p netip.Prefix) uint8 {
	if p.Addr().Is4() {
		return AEIPv4
	}
	return AEIPv6
}

// --- receiving ---

func (s *Speaker) recvLoop(ctx context.Context, conn *gonet.UDPConn) {
	buf := make([]byte, 2048) // real deployments should also raise the peer's own rx buffer past the path MTU
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			return
		}
		src, ok := addrToNetip(addr)
		if !ok {
			continue
		}
		s.mu.Lock()
		neigh := s.byAddr[src]
		s.mu.Unlock()
		if neigh == nil {
			continue // not a configured peer; ignore rather than auto-learn
		}
		s.handlePacket(neigh, buf[:n])
	}
}

func addrToNetip(a net.Addr) (netip.Addr, bool) {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func (s *Speaker) handlePacket(n *neighborState, raw []byte) {
	tlvs, err := DecodePacket(raw)
	if err != nil {
		log.Printf("babel: bad packet from %s: %v", n.addr, err)
		return
	}
	prefixDec := &PrefixDecoder{}
	var curRouterID [8]byte

	for _, t := range tlvs {
		switch t.Type {
		case TLVHello:
			h, err := DecodeHello(t.Body)
			if err != nil {
				continue
			}
			n.mu.Lock()
			n.alive = true
			n.lastHelloTime = time.Now()
			n.helloInterval = time.Duration(h.Interval) * 10 * time.Millisecond
			if h.HasTS {
				n.lastHelloTSTx, n.haveLastHelloTS = h.TSTx, true
			}
			n.mu.Unlock()

		case TLVIHU:
			ihu, _, err := DecodeIHU(t.Body)
			if err != nil {
				continue
			}
			n.mu.Lock()
			n.reportedCost = ihu.RxCost
			n.haveReportedCost = true
			n.ihuExpiry = time.Now().Add(time.Duration(ihu.Interval) * 10 * time.Millisecond * 7 / 2)
			if ihu.HasTS {
				n.measuredRTT = time.Duration(nowMillis()-ihu.TSOrigin) * time.Millisecond
				n.haveRTT = true
			}
			n.mu.Unlock()

		case TLVRouterID:
			id, err := DecodeRouterID(t.Body)
			if err == nil {
				curRouterID = id
			}

		case TLVUpdate:
			u, err := prefixDec.Decode(t.Body)
			if err != nil {
				log.Printf("babel: bad Update from %s: %v", n.addr, err)
				continue
			}
			addr, ok := netip.AddrFromSlice(u.Prefix)
			if !ok {
				continue
			}
			prefix := netip.PrefixFrom(addr.Unmap(), u.Plen)
			ttl := time.Duration(u.Interval) * 10 * time.Millisecond * 7 / 2
			changed, sel := s.routes.update(n, prefix, curRouterID, u.Seqno, u.Metric, ttl)
			if changed {
				if sel != nil && sel.reachable() {
					s.mesh.Routes.Set(prefix, sel.neighbor.peer)
				} else {
					s.mesh.Routes.Remove(prefix)
				}
				s.triggerUpdate()
			}

		case TLVAckReq:
			nonce, err := DecodeAckReq(t.Body)
			if err == nil {
				s.send(n, []RawTLV{EncodeAck(nonce)})
			}
		}
	}
}

func (s *Speaker) neighborDown(n *neighborState) {
	n.mu.Lock()
	n.alive = false
	n.haveReportedCost = false
	n.mu.Unlock()
	for _, prefix := range s.routes.expireNeighbor(n) {
		if sel := s.routes.selectedFor(prefix); sel != nil && sel.reachable() {
			s.mesh.Routes.Set(prefix, sel.neighbor.peer)
		} else {
			s.mesh.Routes.Remove(prefix)
		}
	}
	s.mesh.Routes.RemovePeer(n.peer)
	s.triggerUpdate()
}
