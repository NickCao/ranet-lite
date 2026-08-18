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

	"github.com/NickCao/ranet-lite/internal/esp"
	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1400 // leaves room for outer IP/UDP/ESP overhead under a 1500-byte link MTU

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
		inbound: make(chan []byte, 256),
		done:    make(chan struct{}),
	}
	go m.outboundLoop()
	go m.inboundLoop()
	return m, nil
}

func (m *Mesh) outboundLoop() {
	batch := m.dev.BatchSize()
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65536)
	}
	for {
		n, err := m.dev.Read(bufs, sizes, 0)
		if err != nil {
			return // device closed
		}
		// Dispatch each packet's routing + ESP encryption concurrently
		// rather than one at a time on this single goroutine: sendOut
		// chains into a peer's Seal() (AES-GCM/ChaCha20-Poly1305, CPU-
		// bound) and a UDP write, both safe for concurrent use — Seal
		// only serializes sequence/IV allocation, not the encryption
		// itself (see esp.OutboundSA.nextSeq), and net.UDPConn is safe
		// for concurrent writes. Serializing this on one goroutine would
		// otherwise cap the whole mesh's outbound throughput — every
		// peer, every flow — at one CPU core's encryption rate. Each
		// packet gets its own copy since bufs is reused by the next Read.
		for i := 0; i < n; i++ {
			raw := append([]byte(nil), bufs[i][:sizes[i]]...)
			go m.sendOut(raw)
		}
	}
}

func (m *Mesh) sendOut(raw []byte) {
	src, dst, nh, ok := addrsOf(raw)
	if !ok {
		return
	}
	peer, ok := m.Routes.Lookup(src, dst)
	if !ok {
		return // no route: drop, like any unreachable destination
	}
	_ = peer.sendFn(raw, nh)
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
