package netstack

import (
	"fmt"
	"net/netip"
	"sync"
)

// Peer is one mesh neighbor: sendFn encapsulates a raw tunnel-mode IP packet
// (nextHeader is esp.NextHeaderIPv4/IPv6) and transmits it to that peer.
// Decoupling delivery from the gvisor plumbing this way makes the stack
// wiring testable without real ESP/UDP (see mesh_test.go).
type Peer struct {
	ID     string
	sendFn func(raw []byte, nextHeader byte) error
}

func NewPeer(id string, sendFn func(raw []byte, nextHeader byte) error) *Peer {
	return &Peer{ID: id, sendFn: sendFn}
}

// SendRaw transmits a hand-built tunnel-mode IP packet directly through
// this peer, bypassing the mesh's route table. Used by protocols that
// address a specific peer directly rather than by destination IP — e.g.
// internal/babel, which multicasts through each peer's own ESP tunnel
// rather than routing by the (link-local, often peer-agnostic) destination
// address.
func (p *Peer) SendRaw(raw []byte, nextHeader byte) error {
	return p.sendFn(raw, nextHeader)
}

// RouteTable maps destination prefixes to the peer that can reach them,
// exactly the routes an embedded babel speaker maintains. Longest-prefix
// match, like any IP routing table.
type RouteTable struct {
	mu     sync.RWMutex
	routes []routeEntry
}

type routeEntry struct {
	prefix netip.Prefix
	peer   *Peer
}

func NewRouteTable() *RouteTable {
	return &RouteTable{}
}

// Set installs or replaces the route to prefix.
func (rt *RouteTable) Set(prefix netip.Prefix, peer *Peer) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for i := range rt.routes {
		if rt.routes[i].prefix == prefix {
			rt.routes[i].peer = peer
			return
		}
	}
	rt.routes = append(rt.routes, routeEntry{prefix, peer})
}

// Remove deletes the route to prefix, if any.
func (rt *RouteTable) Remove(prefix netip.Prefix) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for i := range rt.routes {
		if rt.routes[i].prefix == prefix {
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
		out = append(out, fmt.Sprintf("%s via %s", r.prefix, r.peer.ID))
	}
	return out
}

// Lookup returns the peer with the longest matching prefix for addr.
func (rt *RouteTable) Lookup(addr netip.Addr) (*Peer, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	var best *routeEntry
	for i := range rt.routes {
		r := &rt.routes[i]
		if r.prefix.Contains(addr) && (best == nil || r.prefix.Bits() > best.prefix.Bits()) {
			best = r
		}
	}
	if best == nil {
		return nil, false
	}
	return best.peer, true
}
