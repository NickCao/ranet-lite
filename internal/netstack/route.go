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
	reserveFn       func(count int) (BatchSealer, error)
	transmitBatchFn func(sealed [][]byte) error

	reserveMu sync.Mutex
	reserved  uint64
	sendMu    sync.Mutex
	sendCond  *sync.Cond
	nextSend  uint64
}

// BatchSealer consumes a sequence range previously reserved from one outbound
// SA. Calls are made serially by its owning worker; different BatchSealers may
// encrypt concurrently.
type BatchSealer func(raw []byte, nextHeader byte) ([]byte, error)

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

// NewPeerBatched constructs a compatibility peer for an encryptor that cannot
// reserve sequence ranges. Its complete encrypt-and-send operation is ordered,
// so it is safe but intentionally cannot encrypt multiple batches in parallel.
func NewPeerBatched(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), transmitBatchFn func(sealed [][]byte) error) *Peer {
	return newPeer(id, encryptFn, nil, transmitBatchFn)
}

// NewPeerReserved constructs a peer whose expensive encryption can run in
// parallel. reserveFn is called in packet-intake order and must return a sealer
// owning count consecutive sequence numbers from the current outbound SA.
func NewPeerReserved(id string, reserveFn func(count int) (BatchSealer, error), transmitBatchFn func(sealed [][]byte) error) *Peer {
	return newPeer(id, nil, reserveFn, transmitBatchFn)
}

func newPeer(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), reserveFn func(count int) (BatchSealer, error), transmitBatchFn func(sealed [][]byte) error) *Peer {
	p := &Peer{ID: id, encryptFn: encryptFn, reserveFn: reserveFn, transmitBatchFn: transmitBatchFn}
	p.sendCond = sync.NewCond(&p.sendMu)
	return p
}

// SendRaw transmits a hand-built tunnel-mode IP packet directly through this
// peer. Babel uses this path; reserving and transmitting through the same Peer
// as routed traffic keeps its ESP packet ordered with concurrently encrypted
// TUN batches.
func (p *Peer) SendRaw(raw []byte, nextHeader byte) error {
	b := p.reserveBatch(1)
	b.seal(raw, nextHeader)
	return b.transmit()
}

type peerBatch struct {
	peer     *Peer
	ticket   uint64
	reserved bool
	sealer   BatchSealer
	sealed   [][]byte
	raw      [][]byte
	headers  []byte
	err      error
}

// reserveBatch assigns both the peer's transmission ticket and, when
// supported, its ESP sequence range under one lock. Consequently ticket order,
// sequence-range order, and the TUN intake order established by Mesh agree.
func (p *Peer) reserveBatch(count int) *peerBatch {
	p.reserveMu.Lock()
	ticket := p.reserved
	p.reserved++
	b := &peerBatch{peer: p, ticket: ticket, reserved: p.reserveFn != nil}
	if p.reserveFn != nil {
		b.sealer, b.err = p.reserveFn(count)
	}
	p.reserveMu.Unlock()
	if b.reserved {
		b.sealed = make([][]byte, 0, count)
	} else {
		b.raw = make([][]byte, 0, count)
		b.headers = make([]byte, 0, count)
	}
	return b
}

// seal performs AEAD immediately for a range-reserving peer. Compatibility
// peers retain the plaintext until their ordered transmission turn, because
// their encryptFn allocates sequence numbers as part of encryption.
func (b *peerBatch) seal(raw []byte, nextHeader byte) {
	if b.reserved {
		if b.err != nil {
			return
		}
		sealed, err := b.sealer(raw, nextHeader)
		if err != nil {
			b.err = err
			return
		}
		b.sealed = append(b.sealed, sealed)
		return
	}
	b.raw = append(b.raw, raw)
	b.headers = append(b.headers, nextHeader)
}

// transmit waits only at the final ordered-send boundary. Range-reserving
// peers have already encrypted in parallel. The compatibility path encrypts
// here so its scheduler-dependent sequence allocation cannot overtake an
// earlier batch.
func (b *peerBatch) transmit() error {
	p := b.peer
	p.sendMu.Lock()
	for b.ticket != p.nextSend {
		p.sendCond.Wait()
	}
	defer func() {
		p.nextSend++
		p.sendCond.Broadcast()
		p.sendMu.Unlock()
	}()

	if !b.reserved && b.err == nil {
		for i, raw := range b.raw {
			sealed, err := p.encryptFn(raw, b.headers[i])
			if err != nil {
				b.err = err
				continue
			}
			b.sealed = append(b.sealed, sealed)
		}
	}
	if len(b.sealed) != 0 {
		if err := p.transmitBatchFn(b.sealed); err != nil && b.err == nil {
			b.err = err
		}
	}
	return b.err
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
