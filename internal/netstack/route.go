package netstack

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/NickCao/ranet-lite/sadr"
)

// Peer separates parallel packet encryption from ordered, batched transport.
type Peer struct {
	ID              string
	encryptFn       func(raw []byte, nextHeader byte) ([]byte, error)
	transmitBatchFn func(sealed [][]byte) error
}

func NewPeer(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), transmitFn func(sealed []byte) error) *Peer {
	return NewPeerBatched(id, encryptFn, func(sealed [][]byte) error {
		for _, packet := range sealed {
			if err := transmitFn(packet); err != nil {
				return err
			}
		}
		return nil
	})
}

// NewPeerBatched preserves completed TUN batches through the transport handoff.
func NewPeerBatched(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), transmitBatchFn func(sealed [][]byte) error) *Peer {
	return &Peer{ID: id, encryptFn: encryptFn, transmitBatchFn: transmitBatchFn}
}

// SendRaw transmits a hand-built tunnel-mode IP packet directly through
// this peer, bypassing the mesh's route table and its order-preserving
// pipeline. Used by protocols that address a specific peer directly
// rather than by destination IP — e.g. internal/babel, which multicasts
// through each peer's own ESP tunnel rather than routing by the
// (link-local, often peer-agnostic) destination address. Low volume, and
// already strictly sequential relative to itself, so no ordering concern.
func (p *Peer) SendRaw(raw []byte, nextHeader byte) error {
	sealed, err := p.encryptFn(raw, nextHeader)
	if err != nil {
		return err
	}
	return p.transmitBatchFn([][]byte{sealed})
}

type routeKey struct {
	src netip.Prefix
	dst netip.Prefix
}

// RouteTable maps source and destination prefix pairs to peers through the
// generic SADR table. It retains netstack-specific peer removal and diagnostics.
type RouteTable struct {
	table  sadr.Table[*Peer]
	mu     sync.RWMutex
	routes map[routeKey]*Peer
}

func NewRouteTable() *RouteTable {
	return &RouteTable{routes: make(map[routeKey]*Peer)}
}

// Set installs or replaces the route for (src, dst). src may be invalid for
// an ordinary, non-source-specific route.
func (rt *RouteTable) Set(src, dst netip.Prefix, peer *Peer) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.table.Set(src, dst, peer)
	rt.routes[routeKey{src, dst.Masked()}] = peer
}

// Remove deletes the route for (src, dst), if any.
func (rt *RouteTable) Remove(src, dst netip.Prefix) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.table.Remove(src, dst)
	delete(rt.routes, routeKey{src, dst.Masked()})
}

// RemovePeer deletes every route pointing at peer, e.g. when its session dies.
func (rt *RouteTable) RemovePeer(peer *Peer) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.table.RemoveValue(peer)
	for key, value := range rt.routes {
		if value == peer {
			delete(rt.routes, key)
		}
	}
}

// Debug returns a human-readable dump of every installed route.
func (rt *RouteTable) Debug() []string {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := make([]string, 0, len(rt.routes))
	for key, peer := range rt.routes {
		if key.src.IsValid() {
			out = append(out, fmt.Sprintf("%s from %s via %s", key.dst, key.src, peer.ID))
		} else {
			out = append(out, fmt.Sprintf("%s via %s", key.dst, peer.ID))
		}
	}
	return out
}

// Lookup finds the peer that can carry traffic from src to dst.
func (rt *RouteTable) Lookup(src, dst netip.Addr) (*Peer, bool) {
	return rt.table.Lookup(src, dst)
}
