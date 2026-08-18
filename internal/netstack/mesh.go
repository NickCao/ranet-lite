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
	"sync"
	"time"

	"github.com/NickCao/ranet-lite/internal/esp"
	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1400 // leaves room for outer IP/UDP/ESP overhead under a 1500-byte link MTU

// outboundWorkers is the number of long-lived encryption goroutines --
// one per core, shared across every peer -- mirroring wireguard-go's
// device.RoutineEncryption pool exactly (see outboundLoop's doc comment).
var outboundWorkers = min(runtime.NumCPU(), 16)

// outboundContainerBufSize sizes the encryption and order queues in
// units of *containers* (one per Device.Read batch, so up to
// m.dev.BatchSize() packets each), not individual packets -- containers
// are the unit of work here, matching wireguard-go's own queue sizing
// approach of bounding in-flight batches rather than in-flight packets.
const outboundContainerBufSize = 64

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

	dev        tun.Device
	inbound    chan []byte
	encryption chan *outboundElementsContainer // shared across all outboundWorkers
	order      chan *outboundElementsContainer // one per Device.Read batch, in read order
	done       chan struct{}
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
		Routes:     NewRouteTable(),
		Name:       name,
		dev:        dev,
		inbound:    make(chan []byte, chanBufSize),
		encryption: make(chan *outboundElementsContainer, outboundContainerBufSize),
		order:      make(chan *outboundElementsContainer, outboundContainerBufSize),
		done:       make(chan struct{}),
	}
	for i := 0; i < outboundWorkers; i++ {
		go m.encryptionWorker()
	}
	go m.outboundLoop()
	go m.emitter()
	go m.inboundLoop()
	return m, nil
}

// outboundElement is one packet within an outboundElementsContainer, from
// the point its destination peer is resolved through to encryption and
// finally transmission.
type outboundElement struct {
	peer   *Peer // nil: malformed packet or no route, drop
	raw    []byte
	nh     byte
	sealed []byte
	ok     bool // set once encryption succeeds
}

// outboundElementsContainer batches every packet read in one Device.Read
// call, exactly mirroring wireguard-go's device.QueueOutboundElementsContainer
// (device/send.go) -- not a struct we invented, a direct copy of that
// mechanism's shape, since wireguard-go's own type isn't reusable here
// (its fields are unexported, and constructing one requires a full
// device.Device running WireGuard's own Noise-protocol handshake, an
// entirely different, incompatible protocol from our IKEv2/ESP). Its
// embedded mutex is locked before the container is ever queued for
// encryption; whichever encryptionWorker finishes it unlocks it.
// outboundLoop's emitter blocks on that same lock, so it drains
// containers in submission order regardless of which worker encrypted a
// given one or in what order multiple containers finished.
type outboundElementsContainer struct {
	sync.Mutex
	elems []*outboundElement
}

// outboundLoop reads packets from the TUN device in batches -- one
// outboundElementsContainer per Device.Read call -- and hands each
// container to both the shared encryption queue (drained by
// outboundWorkers long-lived goroutines, mirroring wireguard-go's
// device.RoutineEncryption: one pool per core, shared across every peer,
// never pinned by flow) and this mesh's own ordered emitter, which
// transmits each container's packets once encryption finishes it,
// regardless of which worker did the work or how long it took relative
// to other containers. This lets a single peer's single flow encrypt
// across every core while still transmitting in original order -- unlike
// hashing work to a fixed worker (which caps one flow to whatever one
// worker's throughput is) -- and keeps transmitFn calls funneling
// through one path per peer so its own batching/GSO coalescing sees the
// full stream rather than fragments of it. Route lookups happen here,
// synchronously, in read order, not in the encryption workers, so a
// worker only ever needs to touch crypto.
func (m *Mesh) outboundLoop() {
	batch := m.dev.BatchSize()
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65536)
	}
	defer func() {
		close(m.order)
		close(m.encryption)
	}()

	// Temporary diagnostic: is Device.Read actually returning ~batch
	// packets per call, or far fewer despite BatchSize() reporting 128?
	// Logged periodically (not per call) to avoid flooding.
	var (
		reads, packets int64
		lastLog        = time.Now()
	)

	for {
		n, err := m.dev.Read(bufs, sizes, 0)
		if err != nil {
			return // device closed
		}
		reads++
		packets += int64(n)
		if now := time.Now(); now.Sub(lastLog) > 2*time.Second {
			log.Printf("netstack: outboundLoop Read() batch stats: %d reads, %d packets, avg %.1f packets/call (BatchSize()=%d)", reads, packets, float64(packets)/float64(reads), batch)
			reads, packets = 0, 0
			lastLog = now
		}
		c := &outboundElementsContainer{elems: make([]*outboundElement, 0, n)}
		for i := 0; i < n; i++ {
			raw := append([]byte(nil), bufs[i][:sizes[i]]...)
			e := &outboundElement{raw: raw}
			if src, dst, nh, ok := addrsOf(raw); ok {
				if peer, ok := m.Routes.Lookup(src, dst); ok {
					e.peer, e.nh = peer, nh
				}
			}
			c.elems = append(c.elems, e)
		}
		c.Lock()
		select {
		case m.order <- c:
		case <-m.done:
			return
		}
		select {
		case m.encryption <- c:
		case <-m.done:
			return
		}
	}
}

// encryptionWorker is one of outboundWorkers long-lived goroutines
// draining the shared encryption queue -- see outboundLoop's doc comment.
func (m *Mesh) encryptionWorker() {
	for c := range m.encryption {
		for _, e := range c.elems {
			if e.peer == nil {
				continue // malformed packet or no route: leave e.ok false
			}
			sealed, err := e.peer.encryptFn(e.raw, e.nh)
			if err != nil {
				continue
			}
			e.sealed, e.ok = sealed, true
		}
		c.Unlock()
	}
}

// emitter drains containers in the order outboundLoop read them, blocking
// on each one's lock until whichever encryptionWorker sealed it releases
// it -- see outboundLoop's doc comment.
func (m *Mesh) emitter() {
	for c := range m.order {
		c.Lock()
		for _, e := range c.elems {
			if !e.ok {
				continue // malformed packet, no route, or Seal failure: drop
			}
			_ = e.peer.transmitFn(e.sealed)
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
