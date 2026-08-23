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
	"encoding/binary"
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

	devs               []tun.Device
	outboundBufferSize int
	inboundWriters     []chan inboundWriteBatch
	closed             chan struct{}
	closeOnce          sync.Once
	deliveryMu         sync.Mutex
	deliveryWG         sync.WaitGroup
	closing            bool
	writerWG           sync.WaitGroup
}

type inboundWriteBatch struct {
	bufs [][]byte
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
	queueCount := max(1, runtime.GOMAXPROCS(0))
	devs, actualName, err := createTUNQueues(name, mtu, queueCount)
	if err != nil && queueCount == 1 {
		// A pre-existing single-queue TUN rejects an IFF_MULTI_QUEUE attach.
		// Preserve the single-core compatibility path while new interfaces and
		// multicore processes use the scalable multiqueue setup.
		var dev tun.Device
		dev, err = tun.CreateTUN(name, mtu)
		if err == nil {
			actualName, err = dev.Name()
			if err == nil {
				devs = []tun.Device{dev}
			} else {
				_ = dev.Close()
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("netstack: create tun device: %w", err)
	}
	m := &Mesh{
		Routes:             NewRouteTable(),
		Name:               actualName,
		devs:               devs,
		outboundBufferSize: max(mtu, outboundPacketBufferSize),
		closed:             make(chan struct{}),
	}
	m.startInboundWriters()
	// One long-lived worker owns each multiqueue TUN descriptor. This removes
	// the single device read lock while retaining a direct serial path on
	// single-core nodes.
	for _, dev := range m.devs {
		go m.outboundWorker(dev)
	}
	return m, nil
}

// QueueCount reports the number of independent TUN I/O lanes.
func (m *Mesh) QueueCount() int { return len(m.devs) }

// outboundWorker owns a complete packet batch from TUN read through UDP send.
// Every worker reads a different kernel TUN queue, then owns a complete packet
// batch through route lookup and encryption. A peer's reservation lock defines
// the accepted cross-queue order; its final transmission gate sends completed
// ranges in that order, keeping ESP sequence numbers monotonic even when a
// later worker finishes first.
func (m *Mesh) outboundWorker(dev tun.Device) {
	batch := dev.BatchSize()
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
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
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
// packets. On a multiqueue TUN, packets are assigned by their inner flow to a
// persistent writer lane. That preserves each flow's packet order and lets the
// kernel process unrelated streams in parallel. Buffers are copied to leave
// the headroom and tail capacity required by the TUN backend's virtio/GRO
// implementation.
func (m *Mesh) DeliverInboundBatch(raw [][]byte) {
	if len(raw) == 0 {
		return
	}
	m.deliveryMu.Lock()
	if m.closing {
		m.deliveryMu.Unlock()
		return
	}
	m.deliveryWG.Add(1)
	m.deliveryMu.Unlock()
	defer m.deliveryWG.Done()
	if len(m.devs) == 1 {
		m.writeInbound(0, copyInboundPackets(raw))
		return
	}

	groups := make([][][]byte, len(m.devs))
	for _, packet := range raw {
		lane := int(innerFlowHash(packet) % uint64(len(m.devs)))
		groups[lane] = append(groups[lane], packet)
	}
	for lane, packets := range groups {
		if len(packets) == 0 {
			continue
		}
		batch := inboundWriteBatch{bufs: copyInboundPackets(packets)}
		select {
		case m.inboundWriters[lane] <- batch:
		case <-m.closed:
			releaseInboundPackets(batch.bufs)
		}
	}
}

func (m *Mesh) startInboundWriters() {
	if len(m.devs) <= 1 {
		return
	}
	m.inboundWriters = make([]chan inboundWriteBatch, len(m.devs))
	for lane := range m.devs {
		queue := make(chan inboundWriteBatch, 2)
		m.inboundWriters[lane] = queue
		m.writerWG.Add(1)
		go func() {
			defer m.writerWG.Done()
			for {
				select {
				case batch := <-queue:
					m.writeInbound(lane, batch.bufs)
				case <-m.closed:
					// Deliveries that began before Close may still choose the
					// buffered send arm after closed becomes readable. Wait for
					// those sends before the final drain so no pooled buffer is
					// stranded in an abandoned queue.
					m.deliveryWG.Wait()
					for {
						select {
						case batch := <-queue:
							releaseInboundPackets(batch.bufs)
						default:
							return
						}
					}
				}
			}
		}()
	}
}

func copyInboundPackets(raw [][]byte) [][]byte {
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
	return bufs
}

func releaseInboundPackets(bufs [][]byte) {
	for _, buf := range bufs {
		if cap(buf) == inboundPacketBufferSize {
			inboundPacketPool.Put(buf[:inboundPacketBufferSize])
		}
	}
}

func (m *Mesh) writeInbound(lane int, bufs [][]byte) {
	if _, err := m.devs[lane].Write(bufs, writeOffset); err != nil {
		select {
		case <-m.closed:
		default:
			log.Printf("netstack: write to tun device queue %d: %v", lane, err)
		}
	}
	releaseInboundPackets(bufs)
}

// innerFlowHash assigns both directions of an inner TCP/UDP flow to the same
// lane. The commutative endpoint mix is useful for request/response workloads,
// while the final avalanche avoids the sequential-port clustering produced by
// simply taking low hash bits.
func innerFlowHash(packet []byte) uint64 {
	var src, dst []byte
	var protocol byte
	var payload []byte
	fragmented := false
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || headerLength > len(packet) {
			return hashBytes(packet)
		}
		protocol, src, dst = packet[9], packet[12:16], packet[16:20]
		payload = packet[headerLength:]
		fragmented = binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0
	} else if len(packet) >= 40 && packet[0]>>4 == 6 {
		protocol, src, dst = packet[6], packet[8:24], packet[24:40]
		payload = packet[40:]
	} else {
		return hashBytes(packet)
	}

	srcHash, dstHash := hashBytes(src), hashBytes(dst)
	if !fragmented && len(payload) >= 4 && (protocol == 6 || protocol == 17) {
		srcPort := binary.BigEndian.Uint16(payload[:2])
		dstPort := binary.BigEndian.Uint16(payload[2:4])
		srcHash ^= uint64(srcPort) * 0x9e3779b185ebca87
		dstHash ^= uint64(dstPort) * 0x9e3779b185ebca87
	}
	h := srcHash ^ dstHash ^ uint64(protocol)*0x517cc1b727220a95
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	return h ^ h>>31
}

func hashBytes(raw []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, b := range raw {
		h ^= uint64(b)
		h *= 1099511628211
	}
	return h
}

func (m *Mesh) Close() {
	m.closeOnce.Do(func() {
		m.deliveryMu.Lock()
		m.closing = true
		close(m.closed)
		m.deliveryMu.Unlock()
		for _, dev := range m.devs {
			_ = dev.Close()
		}
		m.deliveryWG.Wait()
		m.writerWG.Wait()
	})
}
