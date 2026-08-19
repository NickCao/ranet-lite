package babel

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Babel runs entirely over multicast in this design, and every peer is its
// own point-to-point ESP tunnel — there's no shared L2 segment for gvisor's
// generic IP routing to make sense of "send multicast through peer P".
// So Speaker doesn't use the mesh's netstack for its own wire I/O at all:
// it hand-builds/parses minimal IPv6+UDP packets and hands them directly
// to/from each netstack.Peer's send function and ESP receive loop. Only
// the *routes it learns* go into the shared netstack.RouteTable.

const (
	nextHeaderUDP = 17
	ipv6HeaderLen = 40
	udpHeaderLen  = 8
	babelHopLimit = 1 // link-local multicast must not be forwarded, RFC 8966 §4.1
)

// buildPacket wraps a Babel payload in a minimal IPv6+UDP packet.
func buildPacket(src, dst netip.Addr, payload []byte) []byte {
	total := ipv6HeaderLen + udpHeaderLen + len(payload)
	b := make([]byte, total)

	b[0] = 0x60 // version 6, traffic class/flow label 0
	binary.BigEndian.PutUint16(b[4:6], uint16(udpHeaderLen+len(payload)))
	b[6] = nextHeaderUDP
	b[7] = babelHopLimit
	copy(b[8:24], src.AsSlice())
	copy(b[24:40], dst.AsSlice())

	udp := b[ipv6HeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], Port)
	binary.BigEndian.PutUint16(udp[2:4], Port)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHeaderLen+len(payload)))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(src, dst, udp))
	return b
}

// parsePacket extracts the Babel payload and source address from a raw
// IPv6+UDP packet, rejecting anything not addressed to the Babel port.
func parsePacket(raw []byte, localAddr netip.Addr) (src netip.Addr, payload []byte, err error) {
	if len(raw) < ipv6HeaderLen+udpHeaderLen {
		return netip.Addr{}, nil, fmt.Errorf("babel: packet too short")
	}
	if raw[0]>>4 != 6 {
		return netip.Addr{}, nil, fmt.Errorf("babel: not IPv6")
	}
	if raw[6] != nextHeaderUDP {
		return netip.Addr{}, nil, fmt.Errorf("babel: not UDP")
	}
	payloadLen := int(binary.BigEndian.Uint16(raw[4:6]))
	if payloadLen < udpHeaderLen || ipv6HeaderLen+payloadLen != len(raw) {
		return netip.Addr{}, nil, fmt.Errorf("babel: invalid IPv6 payload length")
	}
	srcAddr, ok := netip.AddrFromSlice(raw[8:24])
	if !ok {
		return netip.Addr{}, nil, fmt.Errorf("babel: bad source address")
	}
	if !srcAddr.Is6() || !srcAddr.IsLinkLocalUnicast() {
		return netip.Addr{}, nil, fmt.Errorf("babel: source is not IPv6 link-local")
	}
	dstAddr, ok := netip.AddrFromSlice(raw[24:40])
	if !ok || (dstAddr != multicastGroup && dstAddr != localAddr) {
		return netip.Addr{}, nil, fmt.Errorf("babel: packet is not addressed to this speaker")
	}
	udp := raw[ipv6HeaderLen:]
	if binary.BigEndian.Uint16(udp[0:2]) != Port {
		return netip.Addr{}, nil, fmt.Errorf("babel: wrong UDP source port")
	}
	dport := binary.BigEndian.Uint16(udp[2:4])
	if dport != Port {
		return netip.Addr{}, nil, fmt.Errorf("babel: not addressed to the babel port")
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen != payloadLen {
		return netip.Addr{}, nil, fmt.Errorf("babel: invalid UDP length")
	}
	receivedChecksum := binary.BigEndian.Uint16(udp[6:8])
	if receivedChecksum == 0 {
		return netip.Addr{}, nil, fmt.Errorf("babel: missing IPv6 UDP checksum")
	}
	checksumInput := append([]byte(nil), udp...)
	checksumInput[6], checksumInput[7] = 0, 0
	if udpChecksum(srcAddr, dstAddr, checksumInput) != receivedChecksum {
		return netip.Addr{}, nil, fmt.Errorf("babel: invalid UDP checksum")
	}
	return srcAddr, udp[udpHeaderLen:udpLen], nil
}

// udpChecksum computes the IPv6 pseudo-header UDP checksum, RFC 8200 §8.1
// — mandatory for UDP over IPv6, unlike IPv4 where zero means "unused".
func udpChecksum(src, dst netip.Addr, udp []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	srcB, dstB := src.As16(), dst.As16()
	add(srcB[:])
	add(dstB[:])
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(udp)))
	add(lenBuf[:])
	var nextHdr [4]byte
	nextHdr[3] = nextHeaderUDP
	add(nextHdr[:])
	add(udp) // checksum field is zero at this point, contributes 0

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	if cs == 0 {
		cs = 0xffff // RFC 8200: a computed checksum of 0 is sent as all-ones
	}
	return cs
}
