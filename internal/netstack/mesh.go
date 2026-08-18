// Package netstack wires a real Linux TUN device to the ranet mesh: outbound
// packets the kernel routes to it are forwarded to whichever peer's Child SA
// can reach the destination (see RouteTable), and inbound packets decrypted
// from any peer are written back to the device as if they'd arrived over any
// other interface. It knows nothing about ESP or IKE directly — peers are
// just a send function plus routes, so this package is testable without real
// crypto (mesh_test.go).
//
// This package never touches the device's address or route configuration —
// creating it and bringing it up is all it does. Assigning an address,
// adding routes (e.g. a default route), and running any local routing daemon
// that wants to peer with the embedded babel speaker are entirely up to
// whoever runs this binary.
package netstack

import (
	"fmt"
	"hash/fnv"
	"log"
	"net/netip"
	"runtime"

	"github.com/NickCao/ranet-lite/internal/esp"
	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1400 // leaves room for outer IP/UDP/ESP overhead under a 1500-byte link MTU

// outboundWorkers bounds how many goroutines process outbound packets
// concurrently. Packets are assigned to a worker by flow hash (see
// flowHash), not round-robin, specifically so parallelism happens across
// flows rather than within one — see outboundLoop's doc comment.
var outboundWorkers = min(runtime.NumCPU(), 16)

// writeOffset is how much leading space Device.Write needs in each buffer
// to prepend its virtio-net header (the tun package always requests
// IFF_VNET_HDR) — the same offset wireguard-go's own device code uses
// (device.MessageTransportOffsetContent) for exactly this reason. Passing
// offset 0 doesn't just lose performance, it fails outright: Write()
// computes offset-virtioNetHdrLen internally and slices from there, so a
// too-small offset is an out-of-range slice.
const writeOffset = 16

// chanBufSize sizes the internal channels absorbing bursts between
// pipeline stages. outboundLoop and inboundLoop both block on these
// channels rather than dropping, so too small a buffer doesn't lose a
// packet directly — it stalls the read loop feeding it, which in turn
// lets the kernel's own fixed-size queue (the tun device's qdisc, 500
// slots by default) back up and drop instead. Matches transport.
// espChanSize for the same underlying reason.
const chanBufSize = 4096

type Mesh struct {
	Routes *RouteTable
	// Name is the TUN device's real interface name (e.g. "ranet0"), as
	// reported by the kernel — needed by whoever configures its address
	// and routes, since the kernel doesn't always honor the requested
	// name exactly.
	Name string

	dev      tun.Device
	inbound  chan []byte
	outbound []chan []byte // indexed by flowHash(raw) % len(outbound)
	done     chan struct{}
}

func New(mtu int) (*Mesh, error) {
	if mtu == 0 {
		mtu = DefaultMTU
	}
	dev, err := tun.CreateTUN("ranet%d", mtu)
	if err != nil {
		return nil, fmt.Errorf("netstack: create tun device: %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("netstack: get tun device name: %w", err)
	}
	m := &Mesh{
		Routes:   NewRouteTable(),
		Name:     name,
		dev:      dev,
		inbound:  make(chan []byte, chanBufSize),
		outbound: make([]chan []byte, outboundWorkers),
		done:     make(chan struct{}),
	}
	for i := range m.outbound {
		m.outbound[i] = make(chan []byte, chanBufSize)
		go m.outboundWorker(i, m.outbound[i])
	}
	go m.outboundLoop()
	go m.inboundLoop()
	return m, nil
}

// outboundLoop reads packets from the TUN device and fans them out across
// outboundWorkers by flow hash. Parallelism has to happen *across* flows,
// not *within* one: encryption completing (and hitting the wire) out of
// the order packets were read is invisible to a protocol like UDP, but a
// TCP receiver reads it as loss and asks the sender to retransmit, which
// is pure waste since nothing was actually lost. Hashing by flow keeps
// every packet of one connection going to the same worker — and so
// staying in relative order — while unrelated flows (e.g. iperf3 -P 8's
// separate streams) still get encrypted fully in parallel across cores.
func (m *Mesh) outboundLoop() {
	batch := m.dev.BatchSize()
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65536)
	}
	defer func() {
		for _, w := range m.outbound {
			close(w)
		}
	}()
	for {
		n, err := m.dev.Read(bufs, sizes, 0)
		if err != nil {
			return // device closed
		}
		for i := 0; i < n; i++ {
			raw := append([]byte(nil), bufs[i][:sizes[i]]...)
			w := m.outbound[flowHash(raw)%uint32(len(m.outbound))]
			select {
			case w <- raw:
			case <-m.done:
				return
			}
		}
	}
}

func (m *Mesh) outboundWorker(shard int, ch chan []byte) {
	for raw := range ch {
		m.sendOut(shard, raw)
	}
}

// sendOut hands raw to whichever peer's route covers it, passing along the
// flow shard (this worker's own index) it was already dispatched to. A
// peer's sendFn threads shard through to the transport so its send-syscall
// work can be parallelized across cores by the same flow, the same way
// outboundLoop already parallelizes encryption -- without this, every
// flow's encrypted packets funnel back into one send goroutine regardless
// of how many encrypt workers ran them, capping a multi-stream transfer's
// syscall-heavy work to a single core no matter how many flows there are.
func (m *Mesh) sendOut(shard int, raw []byte) {
	src, dst, nh, ok := addrsOf(raw)
	if !ok {
		return
	}
	peer, ok := m.Routes.Lookup(src, dst)
	if !ok {
		return // no route: drop, like any unreachable destination
	}
	_ = peer.sendFn(shard, raw, nh)
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
		s, sok := netip.AddrFromSlice(raw[12:16])
		d, dok := netip.AddrFromSlice(raw[16:20])
		return s, d, esp.NextHeaderIPv4, sok && dok
	case 6:
		if len(raw) < 40 {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		s, sok := netip.AddrFromSlice(raw[8:24])
		d, dok := netip.AddrFromSlice(raw[24:40])
		return s, d, esp.NextHeaderIPv6, sok && dok
	default:
		return netip.Addr{}, netip.Addr{}, 0, false
	}
}

// flowHash deterministically hashes a raw IP packet's flow — source,
// destination, protocol, and (for TCP/UDP) ports — so the same flow
// always lands on the same outbound worker. It's a best-effort
// approximation (e.g. IPv6 extension headers before TCP/UDP aren't
// walked), which is fine: getting this wrong only affects load
// distribution across workers, never correctness.
func flowHash(raw []byte) uint32 {
	h := fnv.New32a()
	if len(raw) < 1 {
		return 0
	}
	switch raw[0] >> 4 {
	case 4:
		if len(raw) < 20 {
			return 0
		}
		h.Write(raw[12:20]) // src + dst
		proto := raw[9]
		h.Write([]byte{proto})
		if (proto == 6 || proto == 17) && len(raw) >= 24 {
			h.Write(raw[20:24]) // src port + dst port
		}
	case 6:
		if len(raw) < 40 {
			return 0
		}
		h.Write(raw[8:40]) // src + dst
		proto := raw[6]
		h.Write([]byte{proto})
		if (proto == 6 || proto == 17) && len(raw) >= 44 {
			h.Write(raw[40:44]) // src port + dst port
		}
	default:
		return 0
	}
	return h.Sum32()
}

// DeliverInbound injects an already-decapsulated tunnel-mode IP packet into
// the TUN device, as if it had arrived on the wire. nextHeader is unused —
// the packet's own version nibble is all the kernel needs — but kept for
// symmetry with how peers hand packets to Peer.sendFn. It hands off to
// inboundLoop rather than writing directly so that packets arriving in a
// tight burst (from one or several peers concurrently) get coalesced into
// a single Device.Write call.
func (m *Mesh) DeliverInbound(raw []byte, _ byte) {
	buf := make([]byte, writeOffset+len(raw))
	copy(buf[writeOffset:], raw)
	select {
	case m.inbound <- buf:
	case <-m.done:
	}
}

// inboundLoop batches decrypted packets into as few Device.Write calls as
// possible. Writing one packet per syscall, as a naive implementation
// would, also means the TUN device never sees more than one buffer per
// call, so it can never exercise its own GSO/GRO coalescing for
// same-flow packets — batching here is what lets that actually kick in,
// on top of the more basic win of fewer syscalls under load. It only
// batches what's *already* waiting (a non-blocking drain), so a lone
// packet with nothing queued behind it is written immediately with no
// added latency; batching only happens when arrivals are bursty enough
// that there's really something to gain from it.
func (m *Mesh) inboundLoop() {
	batch := m.dev.BatchSize()
	bufs := make([][]byte, 0, batch)
	for {
		select {
		case <-m.done:
			return
		case buf := <-m.inbound:
			bufs = append(bufs, buf)
		}
	drain:
		for len(bufs) < batch {
			select {
			case buf := <-m.inbound:
				bufs = append(bufs, buf)
			default:
				break drain
			}
		}
		if _, err := m.dev.Write(bufs, writeOffset); err != nil {
			log.Printf("netstack: write to tun device: %v", err)
		}
		bufs = bufs[:0]
	}
}

func (m *Mesh) Close() {
	close(m.done)
	m.dev.Close()
}
