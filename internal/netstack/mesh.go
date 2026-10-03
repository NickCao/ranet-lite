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
// and adding kernel routes to the TUN are the operator's responsibility.
// The embedded Babel speaker exchanges control traffic only inside ESP.
package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"runtime"
	"sync"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/packet"
	"github.com/tailscale/wireguard-go/tun"
)

const DefaultMTU = 1400 // leaves room for outer IP/UDP/ESP overhead under a 1500-byte link MTU

const (
	// Match wireguard-go's batching slab: room for a 64 KiB GSO read plus
	// the headers and spacing added when it is split into individual packets.
	outboundSlabSize      = 2 * (1<<16 - 1)
	inboundWriteBatchSize = 128
	inboundWriteQueueSize = 64
	// Preserve the original receive-pool capacity for throughput. The initial
	// fork migration with 2 KiB buffers regressed in the NixOS comparison.
	inboundPacketBufferSize = writeOffset + 65535
)

var (
	inboundPacketPool = sync.Pool{New: func() any { return make([]byte, inboundPacketBufferSize) }}
)

// writeOffset supplies the headroom required by the platform TUN backends.
// Linux emits its virtio header as a separate writev fragment, but still
// requires an offset of at least the header's length.
const writeOffset = 16

type Mesh struct {
	Routes *RouteTable
	// Name is the TUN device's real interface name (e.g. "ranet0"), as
	// reported by the kernel — needed by whoever configures its address
	// and routes, since the kernel doesn't always honor the requested
	// name exactly.
	Name string

	dev                tun.Device
	queues             []tun.Queue
	outboundJobs       chan *outboundBatch
	outboundFree       chan *outboundBatch
	outboundDispatchMu sync.Mutex
	inboundWriters     []chan inboundWriteBatch
	closed             chan struct{}
	closeOnce          sync.Once
	deliveryMu         sync.Mutex
	deliveryWG         sync.WaitGroup
	closing            bool
	outboundReaderWG   sync.WaitGroup
	outboundWorkerWG   sync.WaitGroup
	writerWG           sync.WaitGroup
}

// outboundBatch owns the TUN buffers from one read until a crypto worker has
// encrypted every routed packet. Readers can therefore immediately continue
// with another buffer set instead of tying one encryption worker to each TUN
// queue (and to whatever flows the kernel happened to hash onto that queue).
type outboundBatch struct {
	n         int
	slab      []byte
	packets   []tun.ReadPacket
	bufs      [][]byte
	peers     []*Peer
	headers   []byte
	counts    map[*Peer]int
	batches   map[*Peer]*peerBatch
	peerOrder []*Peer
}

type inboundWriteBatch struct {
	packets [][]byte
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
	dev, err := createTUN(name, mtu, queueCount)
	if err != nil {
		return nil, fmt.Errorf("netstack: create tun device: %w", err)
	}
	actualName, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("netstack: get tun device name: %w", err)
	}
	if err := bringTUNUp(actualName); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("netstack: bring tun device up: %w", err)
	}
	m := &Mesh{
		Routes: NewRouteTable(),
		Name:   actualName,
		dev:    dev,
		queues: tun.QueuesOf(dev),
		closed: make(chan struct{}),
	}
	m.startInboundWriters()
	m.startOutboundPipeline()
	return m, nil
}

// QueueCount reports the number of independent TUN I/O lanes.
func (m *Mesh) QueueCount() int { return len(m.queues) }

func (m *Mesh) startOutboundPipeline() {
	workers := max(1, runtime.GOMAXPROCS(0))
	m.outboundJobs = make(chan *outboundBatch, 2*workers)
	batchSize := m.dev.BatchSize()
	m.outboundFree = make(chan *outboundBatch, cap(m.outboundJobs)+len(m.queues))
	for range cap(m.outboundFree) {
		m.outboundFree <- m.newOutboundBatch(batchSize)
	}
	for range workers {
		m.outboundWorkerWG.Add(1)
		go m.outboundWorker()
	}
	for _, queue := range m.queues {
		m.outboundReaderWG.Add(1)
		go m.outboundReader(queue)
	}
}

func (m *Mesh) newOutboundBatch(size int) *outboundBatch {
	b := &outboundBatch{
		slab:      make([]byte, outboundSlabSize),
		packets:   make([]tun.ReadPacket, size),
		bufs:      make([][]byte, size),
		peers:     make([]*Peer, size),
		headers:   make([]byte, size),
		counts:    make(map[*Peer]int),
		batches:   make(map[*Peer]*peerBatch),
		peerOrder: make([]*Peer, 0, size),
	}
	return b
}

// outboundReader only reads and classifies packets. Reserving each peer's ESP
// sequence range here fixes the order before independently scheduled workers
// encrypt later batches, so the ordered sender can restore per-flow FIFO.
func (m *Mesh) outboundReader(queue tun.Queue) {
	defer m.outboundReaderWG.Done()
	for {
		var b *outboundBatch
		select {
		case b = <-m.outboundFree:
		case <-m.closed:
			return
		}
		n, err := queue.Read(b.slab, b.packets)
		if err != nil {
			select {
			case <-m.closed:
				return
			default:
				log.Printf("netstack: read from tun device: %v", err)
			}
		}
		b.n = n
		for i := 0; i < n; i++ {
			meta := b.packets[i]
			raw := b.slab[meta.Offset : meta.Offset+meta.Size : meta.Offset+meta.Size]
			b.bufs[i] = raw
			if src, dst, nh, ok := addrsOf(raw); ok {
				if peer, ok := m.Routes.Lookup(src, dst); ok {
					b.peers[i], b.headers[i] = peer, nh
					if b.counts[peer] == 0 {
						b.peerOrder = append(b.peerOrder, peer)
					}
					b.counts[peer]++
				}
			}
		}
		if len(b.peerOrder) == 0 {
			b.reset()
			m.outboundFree <- b
		} else {
			m.dispatchOutbound(b)
		}
		// Read's populated entries remain valid on error. Segment overflow
		// drops only the tail; other errors stop this reader after its batch.
		if err != nil && !errors.Is(err, tun.ErrTooManySegments) {
			return
		}
	}
}

// Reserve and submit each batch as one operation. Otherwise two readers can
// retain the first tickets for different peers while later completed batches
// fill both peers' slots, preventing either reader from reserving its second
// peer. Submission order also keeps compatibility workers from all waiting on
// an earlier ticket that is still queued behind them.
func (m *Mesh) dispatchOutbound(b *outboundBatch) {
	m.outboundDispatchMu.Lock()
	defer m.outboundDispatchMu.Unlock()
	for _, peer := range b.peerOrder {
		b.batches[peer] = peer.reserveBatchUntil(b.counts[peer], m.closed)
	}
	// Workers drain this queue during Close, including every reserved ticket.
	m.outboundJobs <- b
}

func (m *Mesh) outboundWorker() {
	defer m.outboundWorkerWG.Done()
	for b := range m.outboundJobs {
		for i := 0; i < b.n; i++ {
			if peer := b.peers[i]; peer != nil {
				b.batches[peer].append(b.bufs[i], b.headers[i])
			}
		}
		for _, peer := range b.peerOrder {
			if err := b.batches[peer].enqueue(); err != nil {
				log.Printf("netstack: send batch through peer %s: %v", peer.ID, err)
			}
		}
		b.reset()
		select {
		case m.outboundFree <- b:
		case <-m.closed:
		}
	}
}

func (b *outboundBatch) reset() {
	for i := 0; i < b.n; i++ {
		b.peers[i] = nil
		b.bufs[i] = nil
	}
	b.n = 0
	clear(b.counts)
	clear(b.batches)
	clear(b.peerOrder)
	b.peerOrder = b.peerOrder[:0]
}

// addrsOf extracts both the source and destination address from a raw IP
// packet — the route table needs both to support source-specific (SADR)
// routes, not just the destination.
func addrsOf(raw []byte) (src, dst netip.Addr, nextHeader byte, ok bool) {
	src, dst, version := packet.Addrs(raw)
	switch version {
	case 4:
		return src, dst, esp.NextHeaderIPv4, true
	case 6:
		return src, dst, esp.NextHeaderIPv6, true
	default:
		return src, dst, 0, false
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
// the headroom required by the platform TUN backend. Linux GRO gathers
// fragments directly from these packet-sized buffers without repacking them.
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
	if len(m.queues) == 1 {
		for len(raw) != 0 {
			n := min(len(raw), inboundWriteBatchSize)
			m.writeInbound(0, copyInboundPackets(raw[:n]))
			raw = raw[n:]
		}
		return
	}

	groups := make([][][]byte, len(m.queues))
	for _, packet := range raw {
		lane := int(innerFlowHash(packet) % uint64(len(m.queues)))
		groups[lane] = append(groups[lane], packet)
	}
	for lane, packets := range groups {
		if len(packets) == 0 {
			continue
		}
		// The authenticated plaintext remains owned by this queue entry.
		// Deferring the required headroom copy to the writer keeps it off the
		// ordered ESP commit path and lets the writer merge adjacent entries
		// into a larger GRO batch.
		batch := inboundWriteBatch{packets: packets}
		select {
		case m.inboundWriters[lane] <- batch:
		case <-m.closed:
		}
	}
}

func (m *Mesh) startInboundWriters() {
	if len(m.queues) <= 1 {
		return
	}
	m.inboundWriters = make([]chan inboundWriteBatch, len(m.queues))
	for lane := range m.queues {
		queue := make(chan inboundWriteBatch, inboundWriteQueueSize)
		m.inboundWriters[lane] = queue
		m.writerWG.Add(1)
		go func() {
			defer m.writerWG.Done()
			pending := make([][]byte, 0, 2*inboundWriteBatchSize)
			for {
				var first inboundWriteBatch
				select {
				case first = <-queue:
				case <-m.closed:
					// Deliveries that began before Close may still choose the
					// buffered send arm after closed becomes readable. Wait for
					// those sends before abandoning their plaintext references.
					m.deliveryWG.Wait()
					return
				}

				pending = collectReadyInbound(first, queue, pending)
				for offset := 0; offset < len(pending); offset += inboundWriteBatchSize {
					end := min(offset+inboundWriteBatchSize, len(pending))
					m.writeInbound(lane, copyInboundPackets(pending[offset:end]))
				}
				clear(pending)
				pending = pending[:0]
			}
		}()
	}
}

// collectReadyInbound drains only work that is already available. This keeps
// the idle-path latency unchanged while giving a busy writer a full batch for
// NativeTun.Write's GRO pass, reducing the number of TUN write syscalls.
func collectReadyInbound(first inboundWriteBatch, queue <-chan inboundWriteBatch, pending [][]byte) [][]byte {
	pending = append(pending, first.packets...)
	for len(pending) < inboundWriteBatchSize {
		select {
		case batch := <-queue:
			pending = append(pending, batch.packets...)
		default:
			return pending
		}
	}
	return pending
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
	if _, err := tun.WriteToOf(m.dev)(lane, bufs, writeOffset); err != nil {
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
		if m.dev != nil {
			_ = m.dev.Close()
		}
		m.outboundReaderWG.Wait()
		if m.outboundJobs != nil {
			close(m.outboundJobs)
		}
		m.outboundWorkerWG.Wait()
		m.deliveryWG.Wait()
		m.writerWG.Wait()
	})
}
