// Package netstack wires a real Linux TUN device to the ranet mesh: outbound
// packets the kernel routes to it are forwarded to whichever peer's Child SA
// can reach the destination (see RouteTable), and inbound packets decrypted
// from any peer are written back to the device as if they'd arrived over any
// other interface. It knows nothing about ESP or IKE directly — peers are
// just a send function plus routes, so this package is testable without real
// crypto.
//
// This package never touches the device's address or route configuration —
// creating it and bringing it up is all it does. Assigning an address,
// adding routes (e.g. a default route), and running any local routing daemon
// that wants to peer with the embedded babel speaker are entirely up to
// whoever runs this binary.
package netstack

import (
	"fmt"
	"log"
	"net/netip"
	"runtime"
	"sync"

	"github.com/NickCao/ranet-lite/esp"
	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1400 // leaves room for outer IP/UDP/ESP overhead under a 1500-byte link MTU

const (
	outboundPacketBufferSize = 2048
	// inboundPacketBufferSize leaves enough tail capacity for the TUN
	// backend to merge adjacent TCP packets into a single GSO frame before
	// writing it. Exact-capacity packet buffers silently disable that GRO.
	inboundPacketBufferSize = writeOffset + 65535
)

var (
	inboundPacketPool = sync.Pool{New: func() any { return make([]byte, inboundPacketBufferSize) }}
)

// writeOffset is how much leading space Device.Write needs in each buffer
// to prepend its virtio-net header (the tun package always requests
// IFF_VNET_HDR) — the same offset wireguard-go's own device code uses
// (device.MessageTransportOffsetContent) for exactly this reason. Passing
// offset 0 doesn't just lose performance, it fails outright: Write()
// computes offset-virtioNetHdrLen internally and slices from there, so a
// too-small offset is an out-of-range slice.
const writeOffset = 16

type Mesh struct {
	Routes *RouteTable
	// Name is the TUN device's real interface name (e.g. "ranet0"), as
	// reported by the kernel — needed by whoever configures its address
	// and routes, since the kernel doesn't always honor the requested
	// name exactly.
	Name string

	dev                tun.Device
	outboundReadMu     sync.Mutex
	outboundBufferSize int
}

// New creates an automatically named TUN device.
func New(mtu int) (*Mesh, error) { return NewNamed(mtu, "") }

// NewNamed attaches to or creates name through wireguard-go's TUN backend.
// An empty name retains the project's automatically assigned ranet%d name.
func NewNamed(mtu int, name string) (*Mesh, error) {
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if name == "" {
		name = "ranet%d"
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("netstack: create tun device: %w", err)
	}
	actualName, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("netstack: get tun device name: %w", err)
	}
	m := &Mesh{
		Routes:             NewRouteTable(),
		Name:               actualName,
		dev:                dev,
		outboundBufferSize: max(mtu, outboundPacketBufferSize),
	}
	// One long-lived worker per available Go execution context lets packet
	// batches encrypt concurrently without per-packet goroutines or scheduler
	// queues. On single-core nodes this naturally remains the direct serial
	// path measured to perform best.
	for range max(1, runtime.GOMAXPROCS(0)) {
		go m.outboundWorker()
	}
	return m, nil
}

// outboundWorker owns a complete packet batch from TUN read through UDP send.
// The read lock extends the TUN backend's own serialized read through route
// lookup and sequence-range reservation. It is released before AEAD work, so
// another worker can reserve the next range and encrypt it concurrently. Each
// peer's final transmission gate then sends completed ranges in reservation
// order, keeping ESP sequence numbers monotonic even when a later worker
// finishes first.
func (m *Mesh) outboundWorker() {
	batch := m.dev.BatchSize()
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	peers := make([]*Peer, batch)
	headers := make([]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, m.outboundBufferSize)
	}
	counts := make(map[*Peer]int)
	batches := make(map[*Peer]*peerBatch)
	peerOrder := make([]*Peer, 0, batch)

	for {
		m.outboundReadMu.Lock()
		n, err := m.dev.Read(bufs, sizes, 0)
		if err != nil {
			m.outboundReadMu.Unlock()
			return // device closed
		}
		clear(counts)
		clear(batches)
		peerOrder = peerOrder[:0]
		for i := 0; i < n; i++ {
			peers[i] = nil
			raw := bufs[i][:sizes[i]]
			if src, dst, nh, ok := addrsOf(raw); ok {
				if peer, ok := m.Routes.Lookup(src, dst); ok {
					peers[i], headers[i] = peer, nh
					if counts[peer] == 0 {
						peerOrder = append(peerOrder, peer)
					}
					counts[peer]++
				}
			}
		}
		for _, peer := range peerOrder {
			batches[peer] = peer.reserveBatch(counts[peer])
		}
		m.outboundReadMu.Unlock()

		for i := 0; i < n; i++ {
			if peer := peers[i]; peer != nil {
				batches[peer].seal(bufs[i][:sizes[i]], headers[i])
			}
		}
		for _, peer := range peerOrder {
			if err := batches[peer].enqueue(); err != nil {
				log.Printf("netstack: send batch through peer %s: %v", peer.ID, err)
			}
		}
	}
}

// addrsOf extracts both the source and destination address from a raw IP
// packet — the route table needs both to support source-specific (SADR)
// routes, not just the destination.
func addrsOf(raw []byte) (src, dst netip.Addr, nextHeader byte, ok bool) {
	if len(raw) < 1 {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	switch raw[0] >> 4 {
	case 4:
		if len(raw) < 20 {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		headerLength := int(raw[0]&0x0f) * 4
		totalLength := int(raw[2])<<8 | int(raw[3])
		if headerLength < 20 || headerLength > len(raw) || totalLength < headerLength || totalLength != len(raw) {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		s, sok := netip.AddrFromSlice(raw[12:16])
		d, dok := netip.AddrFromSlice(raw[16:20])
		return s, d, esp.NextHeaderIPv4, sok && dok
	case 6:
		if len(raw) < 40 {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		payloadLength := int(raw[4])<<8 | int(raw[5])
		if 40+payloadLength != len(raw) {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		s, sok := netip.AddrFromSlice(raw[8:24])
		d, dok := netip.AddrFromSlice(raw[24:40])
		return s, d, esp.NextHeaderIPv6, sok && dok
	default:
		return netip.Addr{}, netip.Addr{}, 0, false
	}
}

// DeliverInbound injects an already-decapsulated tunnel-mode IP packet into
// the TUN device, as if it had arrived on the wire.
func (m *Mesh) DeliverInbound(raw []byte) {
	m.DeliverInboundBatch([][]byte{raw})
}

// DeliverInboundBatch injects a group of already-decapsulated tunnel-mode IP
// packets directly in one write batch. The calling receive worker retains
// ownership through this TUN write; there is no channel handoff or separate
// emitter. Buffers are copied to leave the headroom and tail capacity required
// by the TUN backend's virtio/GRO implementation.
func (m *Mesh) DeliverInboundBatch(raw [][]byte) {
	if len(raw) == 0 {
		return
	}
	bufs := make([][]byte, len(raw))
	for i := range raw {
		buf := inboundPacketPool.Get().([]byte)
		if cap(buf) < writeOffset+len(raw[i]) {
			buf = make([]byte, writeOffset+len(raw[i]))
		} else {
			buf = buf[:writeOffset+len(raw[i])]
		}
		bufs[i] = buf
		copy(bufs[i][writeOffset:], raw[i])
	}
	if _, err := m.dev.Write(bufs, writeOffset); err != nil {
		log.Printf("netstack: write to tun device: %v", err)
	}
	for _, buf := range bufs {
		if cap(buf) == inboundPacketBufferSize {
			inboundPacketPool.Put(buf[:inboundPacketBufferSize])
		}
	}
}

func (m *Mesh) Close() {
	m.dev.Close()
}
