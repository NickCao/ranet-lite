package babel

import (
	"net/netip"
	"sync"
	"time"
)

// routeKey identifies one routing table entry: an ordinary route has an
// invalid (zero-value) Source, matching any source address; a
// source-specific (SADR) route has a real Source prefix and is tracked
// completely independently from any ordinary route to the same
// destination, exactly as draft-ietf-babel-source-specific requires.
type routeKey struct {
	source netip.Prefix
	dest   netip.Prefix
}

// routeInfo is what we know about one candidate path to a routeKey,
// learned from a single neighbor's Update TLVs.
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

// keyEntry tracks every known candidate route to a routeKey plus which one
// is currently selected/installed.
type keyEntry struct {
	key      routeKey
	routes   map[*neighborState]*routeInfo // one candidate per neighbor
	selected *routeInfo
}

// routeTable is shared between the receive loop (handlePacket -> update)
// and the timer loop (flushUpdates / sweepExpired), so every access must
// go through mu.
type routeTable struct {
	mu      sync.Mutex
	entries map[routeKey]*keyEntry
}

func newRouteTable() *routeTable {
	return &routeTable{entries: map[routeKey]*keyEntry{}}
}

// update processes one received Update and reports whether the selected
// route for this key changed (so the caller can push it to
// netstack.RouteTable and re-advertise to other peers).
func (rt *routeTable) update(n *neighborState, key routeKey, routerID [8]byte, seqno, metric uint16, ttl time.Duration) (changed bool, sel *routeInfo) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	ke, ok := rt.entries[key]
	if !ok {
		ke = &keyEntry{key: key, routes: map[*neighborState]*routeInfo{}}
		rt.entries[key] = ke
	}

	cost := metric
	if metric < MetricInfinity {
		cost = saturatingAdd(n.linkCost(), metric)
	}
	cand := &routeInfo{neighbor: n, routerID: routerID, seqno: seqno, rxMetric: metric, cost: cost, expiresAt: time.Now().Add(ttl)}
	ke.routes[n] = cand

	prevSelected := ke.selected
	switch {
	case ke.selected == nil || ke.selected.neighbor == n:
		// Always accept a refresh/change from the currently selected
		// neighbor (including retraction via MetricInfinity).
		ke.selected = cand
	case metric < MetricInfinity && feasible(cand, ke.selected) && cand.cost < ke.selected.cost:
		ke.selected = cand
	}

	if ke.selected != nil && !ke.selected.reachable() {
		ke.selected = ke.bestReachable()
	}

	changed = prevSelected != ke.selected &&
		(prevSelected == nil || ke.selected == nil || prevSelected.neighbor != ke.selected.neighbor || prevSelected.cost != ke.selected.cost)
	return changed, ke.selected
}

func (ke *keyEntry) bestReachable() *routeInfo {
	var best *routeInfo
	for _, r := range ke.routes {
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
// down, re-selecting a fallback route per key where one exists.
func (rt *routeTable) expireNeighbor(n *neighborState) (changed []routeKey) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for key, ke := range rt.entries {
		if _, ok := ke.routes[n]; !ok {
			continue
		}
		delete(ke.routes, n)
		if ke.selected != nil && ke.selected.neighbor == n {
			ke.selected = ke.bestReachable()
			changed = append(changed, key)
		}
	}
	return changed
}

// sweepExpired re-evaluates every selected route's TTL — needed because
// update() only re-checks reachability reactively, when a fresh Update for
// that key arrives. A neighbor that stops sending updates entirely (not
// just Hello) would otherwise never be noticed. install is called with the
// new selected route (nil if the key is now unreachable) for every key
// whose selection changed.
func (rt *routeTable) sweepExpired(install func(key routeKey, sel *routeInfo)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for key, ke := range rt.entries {
		if ke.selected != nil && !ke.selected.reachable() {
			ke.selected = ke.bestReachable()
			install(key, ke.selected)
		}
	}
}

// selectedFor returns the currently selected route for key, if any.
func (rt *routeTable) selectedFor(key routeKey) *routeInfo {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if ke := rt.entries[key]; ke != nil {
		return ke.selected
	}
	return nil
}
