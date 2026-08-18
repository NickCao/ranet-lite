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
	"log"
	"net/netip"
	"runtime"

	"github.com/NickCao/ranet-lite/internal/esp"
	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1400 // leaves room for outer IP/UDP/ESP overhead under a 1500-byte link MTU

// outboundWorkers bounds how many packets can have encryption in flight
// concurrently across all peers combined -- see outboundLoop's doc
// comment for why this is a shared pool rather than work pinned to a
// fixed worker per peer or flow.
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

	dev     tun.Device
	inbound chan []byte
	done    chan struct{}
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
		Routes:  NewRouteTable(),
		Name:    name,
		dev:     dev,
		inbound: make(chan []byte, chanBufSize),
		done:    make(chan struct{}),
	}
	go m.outboundLoop()
	go m.inboundLoop()
	return m, nil
}

// outboundLoop reads packets from the TUN device, encrypting them across
// as many parallel workers as there are cores regardless of which peer or
// flow a packet belongs to -- mirroring wireguard-go's own device.
// RoutineEncryption pool (one instance per core, shared across every
// peer, not pinned by flow). Parallel encryption completing out of the
// order packets were read is invisible to a protocol like UDP, but a TCP
// receiver reads it as loss and asks the sender to retransmit, which is
// pure waste since nothing was actually lost -- so before a packet's
// encryption even starts, it reserves a delivery slot in read order (a
// 1-buffered result channel), and a single emitter drains slots in that
// same order, calling Peer.transmitFn once each one resolves. Slow and
// fast packets can still finish encrypting out of order without ever
// being *transmitted* out of order. This lets a single peer's single flow
// use every core for encryption, unlike hashing work to a fixed worker
// (which caps one flow to whatever one worker's throughput is), and keeps
// transmitFn calls funneling through one path per peer so its own
// batching/GSO coalescing sees the full stream rather than fragments of
// it.
func (m *Mesh) outboundLoop() {
	batch := m.dev.BatchSize()
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65536)
	}

	type job struct {
		peer   *Peer
		sealed []byte
		ok     bool
	}
	order := make(chan chan job, chanBufSize)
	sem := make(chan struct{}, outboundWorkers)
	emitterDone := make(chan struct{})
	go func() {
		defer close(emitterDone)
		for slot := range order {
			j := <-slot
			if !j.ok {
				continue // malformed packet, no route, or Seal failure: drop
			}
			_ = j.peer.transmitFn(j.sealed)
		}
	}()
	defer func() {
		close(order)
		<-emitterDone
	}()

	for {
		n, err := m.dev.Read(bufs, sizes, 0)
		if err != nil {
			return // device closed
		}
		for i := 0; i < n; i++ {
			raw := append([]byte(nil), bufs[i][:sizes[i]]...)
			slot := make(chan job, 1)
			select {
			case order <- slot:
			case <-m.done:
				return
			}
			select {
			case sem <- struct{}{}:
			case <-m.done:
				return
			}
			go func(raw []byte, slot chan job) {
				defer func() { <-sem }()
				src, dst, nh, ok := addrsOf(raw)
				if !ok {
					slot <- job{}
					return
				}
				peer, ok := m.Routes.Lookup(src, dst)
				if !ok {
					slot <- job{} // no route: drop, like any unreachable destination
					return
				}
				sealed, err := peer.encryptFn(raw, nh)
				if err != nil {
					slot <- job{}
					return
				}
				slot <- job{peer: peer, sealed: sealed, ok: true}
			}(raw, slot)
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

// DeliverInbound injects an already-decapsulated tunnel-mode IP packet into
// the TUN device, as if it had arrived on the wire. nextHeader is unused —
// the packet's own version nibble is all the kernel needs — but kept for
// symmetry with how peers hand packets to Peer.encryptFn. It hands off to
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
