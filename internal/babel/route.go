package babel

import (
	"net/netip"
	"sync"
	"time"
)

// routeInfo is what we know about one candidate path to a prefix, learned
// from a single neighbor's Update TLVs.
type routeInfo struct {
	neighbor  *neighborState
	routerID  [8]byte
	seqno     uint16
	rxMetric  uint16 // metric as advertised by the neighbor (their cost to the prefix)
	cost      uint16 // our total cost via this neighbor: link cost + rxMetric
	expiresAt time.Time
}

func (r *routeInfo) reachable() bool {
	return r.rxMetric < MetricInfinity && time.Now().Before(r.expiresAt)
}

// feasible implements the RFC 8966 §3.5.1 feasibility condition against
// the current best route for the same prefix: a candidate replaces the
// selected route only if it strictly improves (lower seqno-adjusted
// metric) or comes from a newer seqno — this is what prevents routing
// loops in a distance-vector protocol.
func feasible(candidate, current *routeInfo) bool {
	if current == nil {
		return true
	}
	if seqnoGT(candidate.seqno, current.seqno) {
		return true
	}
	if candidate.seqno == current.seqno && candidate.rxMetric < current.rxMetric {
		return true
	}
	return false
}

// seqnoGT compares Babel sequence numbers with the wraparound-aware rule
// from RFC 8966 §3.2.2 (i.e. "greater" means "less than 32768 ahead of").
func seqnoGT(a, b uint16) bool {
	return int16(a-b) > 0
}

// prefixEntry tracks every known candidate route to a prefix plus which
// one is currently selected/installed.
type prefixEntry struct {
	prefix   netip.Prefix
	routes   map[*neighborState]*routeInfo // one candidate per neighbor
	selected *routeInfo
}

// routeTable is shared between the receive loop (handlePacket -> update)
// and the timer loop (flushUpdates / sweepExpired), so every access must
// go through mu.
type routeTable struct {
	mu      sync.Mutex
	entries map[netip.Prefix]*prefixEntry
}

func newRouteTable() *routeTable {
	return &routeTable{entries: map[netip.Prefix]*prefixEntry{}}
}

// update processes one received Update and reports whether the selected
// route for this prefix changed (so the caller can push it to
// netstack.RouteTable and re-advertise to other peers).
func (rt *routeTable) update(n *neighborState, prefix netip.Prefix, routerID [8]byte, seqno, metric uint16, ttl time.Duration) (changed bool, sel *routeInfo) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	pe, ok := rt.entries[prefix]
	if !ok {
		pe = &prefixEntry{prefix: prefix, routes: map[*neighborState]*routeInfo{}}
		rt.entries[prefix] = pe
	}

	cost := metric
	if metric < MetricInfinity {
		cost = saturatingAdd(n.linkCost(), metric)
	}
	cand := &routeInfo{neighbor: n, routerID: routerID, seqno: seqno, rxMetric: metric, cost: cost, expiresAt: time.Now().Add(ttl)}
	pe.routes[n] = cand

	prevSelected := pe.selected
	switch {
	case pe.selected == nil || pe.selected.neighbor == n:
		// Always accept a refresh/change from the currently selected
		// neighbor (including retraction via MetricInfinity).
		pe.selected = cand
	case metric < MetricInfinity && feasible(cand, pe.selected) && cand.cost < pe.selected.cost:
		pe.selected = cand
	}

	if pe.selected != nil && !pe.selected.reachable() {
		pe.selected = pe.bestReachable()
	}

	changed = prevSelected != pe.selected &&
		(prevSelected == nil || pe.selected == nil || prevSelected.neighbor != pe.selected.neighbor || prevSelected.cost != pe.selected.cost)
	return changed, pe.selected
}

func (pe *prefixEntry) bestReachable() *routeInfo {
	var best *routeInfo
	for _, r := range pe.routes {
		if !r.reachable() {
			continue
		}
		if best == nil || r.cost < best.cost {
			best = r
		}
	}
	return best
}

// expireNeighbor drops every route learned from a neighbor that just went
// down, re-selecting a fallback route per prefix where one exists.
func (rt *routeTable) expireNeighbor(n *neighborState) (changed []netip.Prefix) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for prefix, pe := range rt.entries {
		if _, ok := pe.routes[n]; !ok {
			continue
		}
		delete(pe.routes, n)
		if pe.selected != nil && pe.selected.neighbor == n {
			pe.selected = pe.bestReachable()
			changed = append(changed, prefix)
		}
	}
	return changed
}

// sweepExpired re-evaluates every selected route's TTL — needed because
// update() only re-checks reachability reactively, when a fresh Update for
// that prefix arrives. A neighbor that stops sending updates entirely
// (not just Hello) would otherwise never be noticed. install is called
// with the new selected route (nil if the prefix is now unreachable) for
// every prefix whose selection changed.
func (rt *routeTable) sweepExpired(install func(prefix netip.Prefix, sel *routeInfo)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for prefix, pe := range rt.entries {
		if pe.selected != nil && !pe.selected.reachable() {
			pe.selected = pe.bestReachable()
			install(prefix, pe.selected)
		}
	}
}

// selectedFor returns the currently selected route for prefix, if any.
func (rt *routeTable) selectedFor(prefix netip.Prefix) *routeInfo {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if pe := rt.entries[prefix]; pe != nil {
		return pe.selected
	}
	return nil
}

// snapshotSelected returns the currently selected route for every prefix,
// for building outgoing Update TLVs without holding the lock while sending.
func (rt *routeTable) snapshotSelected() map[netip.Prefix]*routeInfo {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make(map[netip.Prefix]*routeInfo, len(rt.entries))
	for prefix, pe := range rt.entries {
		if pe.selected != nil {
			out[prefix] = pe.selected
		}
	}
	return out
}
