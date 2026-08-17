// Package netstack wires a gvisor userspace TCP/IP stack to the ranet mesh:
// one NIC backed by a channel.Endpoint, with outbound packets routed to
// whichever peer's Child SA can reach the destination (see RouteTable) and
// inbound packets from any peer injected back into the stack. It knows
// nothing about ESP or IKE directly — peers are just a send function plus
// routes, so this package is testable without real crypto (mesh_test.go).
package netstack

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/nickcao/ranet-client/internal/esp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	NICID      = tcpip.NICID(1)
	DefaultMTU = 1400 // leaves room for outer IP/UDP/ESP overhead under a 1500-byte link MTU
)

type Mesh struct {
	Stack  *stack.Stack
	Routes *RouteTable
	ep     *channel.Endpoint
}

func New(mtu uint32) (*Mesh, error) {
	if mtu == 0 {
		mtu = DefaultMTU
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(256, mtu, "")
	if err := s.CreateNIC(NICID, ep); err != nil {
		return nil, fmt.Errorf("netstack: create NIC: %s", err)
	}
	// This client only ever originates/terminates traffic for addresses
	// reachable via babel-learned routes, never a fixed local subnet, so
	// promiscuous+spoofing (accept/send for any address on the NIC) is the
	// right posture rather than pinning a single interface address.
	if err := s.SetSpoofing(NICID, true); err != nil {
		return nil, fmt.Errorf("netstack: set spoofing: %s", err)
	}
	if err := s.SetPromiscuousMode(NICID, true); err != nil {
		return nil, fmt.Errorf("netstack: set promiscuous: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: NICID},
		{Destination: header.IPv6EmptySubnet, NIC: NICID},
	})
	m := &Mesh{Stack: s, ep: ep, Routes: NewRouteTable()}
	go m.outboundLoop()
	return m, nil
}

// AddLocalAddress assigns this node's own mesh-reachable address to the
// stack, giving gonet.Dial{TCP,UDP} a source address and letting inbound
// connections addressed to it be delivered locally.
func (m *Mesh) AddLocalAddress(addr netip.Addr) error {
	proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
	if addr.Is6() {
		proto = ipv6.ProtocolNumber
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol: proto,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr.AsSlice()),
			PrefixLen: addr.BitLen(),
		},
	}
	if err := m.Stack.AddProtocolAddress(NICID, protoAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("netstack: add local address %s: %s", addr, err)
	}
	return nil
}

func (m *Mesh) outboundLoop() {
	for {
		pkt := m.ep.ReadContext(context.Background())
		if pkt == nil {
			return // endpoint closed
		}
		raw := append([]byte{}, pkt.ToView().AsSlice()...)
		pkt.DecRef()
		m.sendOut(raw)
	}
}

func (m *Mesh) sendOut(raw []byte) {
	dst, nh, ok := destOf(raw)
	if !ok {
		return
	}
	peer, ok := m.Routes.Lookup(dst)
	if !ok {
		return // no route: drop, like any unreachable destination
	}
	_ = peer.sendFn(raw, nh)
}

func destOf(raw []byte) (netip.Addr, byte, bool) {
	if len(raw) < 1 {
		return netip.Addr{}, 0, false
	}
	switch raw[0] >> 4 {
	case 4:
		if len(raw) < 20 {
			return netip.Addr{}, 0, false
		}
		a, ok := netip.AddrFromSlice(raw[16:20])
		return a, esp.NextHeaderIPv4, ok
	case 6:
		if len(raw) < 40 {
			return netip.Addr{}, 0, false
		}
		a, ok := netip.AddrFromSlice(raw[24:40])
		return a, esp.NextHeaderIPv6, ok
	default:
		return netip.Addr{}, 0, false
	}
}

// DeliverInbound injects an already-decapsulated tunnel-mode IP packet
// (nextHeader is esp.NextHeaderIPv4/IPv6) into the stack, as if it had
// arrived on the wire. The stack doesn't need to know which peer decrypted
// it — only outbound routing does.
func (m *Mesh) DeliverInbound(raw []byte, nextHeader byte) {
	var proto tcpip.NetworkProtocolNumber
	switch nextHeader {
	case esp.NextHeaderIPv4:
		proto = ipv4.ProtocolNumber
	case esp.NextHeaderIPv6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	m.ep.InjectInbound(proto, pkt)
	pkt.DecRef()
}

func (m *Mesh) Close() {
	m.ep.Close()
	m.Stack.Close()
}
