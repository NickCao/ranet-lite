package netstack

import (
	"fmt"
	"net/netip"
	"sync"
)

// Peer is one mesh neighbor: sendFn encapsulates a raw tunnel-mode IP packet
// (nextHeader is esp.NextHeaderIPv4/IPv6) and transmits it to that peer.
// shard is the flow-hash worker index the packet was dispatched to by
// Mesh.outboundLoop (see its doc comment) -- sendFn's transport is expected
// to use it to keep that same flow's send-syscall work on a consistent,
// parallelizable lane, the same way encryption already is. Decoupling
// delivery from the TUN plumbing this way makes the stack wiring testable
// without a real TUN device or ESP/UDP (see mesh_test.go).
type Peer struct {
	ID     string
	sendFn func(shard int, raw []byte, nextHeader byte) error
}

func NewPeer(id string, sendFn func(shard int, raw []byte, nextHeader byte) error) *Peer {
	return &Peer{ID: id, sendFn: sendFn}
}

// SendRaw transmits a hand-built tunnel-mode IP packet directly through
// this peer, bypassing the mesh's route table. Used by protocols that
// address a specific peer directly rather than by destination IP — e.g.
// internal/babel, which multicasts through each peer's own ESP tunnel
// rather than routing by the (link-local, often peer-agnostic) destination
// address. There's no flow to shard by for control traffic like this, and
// no throughput concern either, so it always uses shard 0.
func (p *Peer) SendRaw(raw []byte, nextHeader byte) error {
	return p.sendFn(0, raw, nextHeader)
}

// RouteTable maps (source, destination) prefix pairs to the peer that can
// reach them — including source-specific (SADR,
// draft-ietf-babel-source-specific) routes, which an embedded babel
// speaker installs directly rather than approximating: since this mesh's
// own TUN device sees every packet's real source and destination address
// directly, there's no need to guess whether a source-specific route
// "applies to us" the way a destination-only route table would have to.
//
// An invalid (zero-value) Source prefix means "any source", i.e. an
// ordinary, non-source-specific route.
type RouteTable struct {
	mu     sync.RWMutex
	routes []routeEntry
}

type routeEntry struct {
	src  netip.Prefix // invalid (zero value) means "any source"
	dst  netip.Prefix
	peer *Peer
}

func NewRouteTable() *RouteTable {
	return &RouteTable{}
}

// Set installs or replaces the route for (src, dst). src may be the zero
// netip.Prefix{} for an ordinary, non-source-specific route.
func (rt *RouteTable) Set(src, dst netip.Prefix, peer *Peer) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for i := range rt.routes {
		if rt.routes[i].src == src && rt.routes[i].dst == dst {
			rt.routes[i].peer = peer
			return
		}
	}
	rt.routes = append(rt.routes, routeEntry{src, dst, peer})
}

// Remove deletes the route for (src, dst), if any.
func (rt *RouteTable) Remove(src, dst netip.Prefix) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for i := range rt.routes {
		if rt.routes[i].src == src && rt.routes[i].dst == dst {
			rt.routes = append(rt.routes[:i], rt.routes[i+1:]...)
			return
		}
	}
}

// RemovePeer deletes every route pointing at peer, e.g. when its session dies.
func (rt *RouteTable) RemovePeer(peer *Peer) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	kept := rt.routes[:0]
	for _, r := range rt.routes {
		if r.peer != peer {
			kept = append(kept, r)
		}
	}
	rt.routes = kept
}

// Debug returns a human-readable dump of every installed route, for
// diagnostics/tests — not meant for programmatic use.
func (rt *RouteTable) Debug() []string {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := make([]string, 0, len(rt.routes))
	for _, r := range rt.routes {
		if r.src.IsValid() {
			out = append(out, fmt.Sprintf("%s from %s via %s", r.dst, r.src, r.peer.ID))
		} else {
			out = append(out, fmt.Sprintf("%s via %s", r.dst, r.peer.ID))
		}
	}
	return out
}

// Lookup finds the peer that can carry traffic from src to dst, per
// draft-ietf-babel-source-specific's selection rule: the destination
// match is resolved first (longest destination prefix wins); only among
// entries tied on destination specificity does the source prefix act as a
// tiebreaker, so a source-specific entry is preferred over an any-source
// one at the same destination specificity, but never overrides a more
// specific destination match.
func (rt *RouteTable) Lookup(src, dst netip.Addr) (*Peer, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	var best *routeEntry
	for i := range rt.routes {
		r := &rt.routes[i]
		if !r.dst.Contains(dst) {
			continue
		}
		if r.src.IsValid() && !r.src.Contains(src) {
			continue
		}
		if best == nil || betterRoute(r, best) {
			best = r
		}
	}
	if best == nil {
		return nil, false
	}
	return best.peer, true
}

func betterRoute(a, b *routeEntry) bool {
	if a.dst.Bits() != b.dst.Bits() {
		return a.dst.Bits() > b.dst.Bits()
	}
	return srcBits(a.src) > srcBits(b.src)
}

// srcBits treats "any source" as less specific than every real prefix,
// including /0, so it always loses a tie against a genuine source match.
func srcBits(p netip.Prefix) int {
	if !p.IsValid() {
		return -1
	}
	return p.Bits()
}
