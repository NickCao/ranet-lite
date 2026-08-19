package ike

import (
	"encoding/binary"
	"fmt"
	"net"
)

// --- Key Exchange payload, RFC 7296 §3.4 ---

func EncodeKE(group uint16, pub []byte) []byte {
	b := make([]byte, 4+len(pub))
	binary.BigEndian.PutUint16(b[0:2], group)
	copy(b[4:], pub)
	return b
}

func DecodeKE(body []byte) (group uint16, pub []byte, err error) {
	if len(body) < 4 {
		return 0, nil, fmt.Errorf("ike: short KE payload")
	}
	return binary.BigEndian.Uint16(body[0:2]), body[4:], nil
}

// --- Nonce payload, RFC 7296 §3.9 ---

func EncodeNonce(n []byte) []byte    { return n }
func DecodeNonce(body []byte) []byte { return body }

// --- Notify payload, RFC 7296 §3.10 ---

type Notify struct {
	Protocol ProtocolID // 0 if not protocol-specific
	SPI      []byte
	Type     NotifyType
	Data     []byte
}

func EncodeNotify(n Notify) []byte {
	b := make([]byte, 4+len(n.SPI)+len(n.Data))
	b[0] = byte(n.Protocol)
	b[1] = byte(len(n.SPI))
	binary.BigEndian.PutUint16(b[2:4], uint16(n.Type))
	copy(b[4:], n.SPI)
	copy(b[4+len(n.SPI):], n.Data)
	return b
}

func DecodeNotify(body []byte) (Notify, error) {
	if len(body) < 4 {
		return Notify{}, fmt.Errorf("ike: short notify payload")
	}
	spiSize := int(body[1])
	if len(body) < 4+spiSize {
		return Notify{}, fmt.Errorf("ike: notify SPI truncated")
	}
	return Notify{
		Protocol: ProtocolID(body[0]),
		SPI:      append([]byte{}, body[4:4+spiSize]...),
		Type:     NotifyType(binary.BigEndian.Uint16(body[2:4])),
		Data:     append([]byte{}, body[4+spiSize:]...),
	}, nil
}

// --- Delete payload, RFC 7296 §3.11 ---

type Delete struct {
	Protocol ProtocolID
	SPIs     [][]byte
}

func EncodeDelete(d Delete) []byte {
	spiSize := 0
	if len(d.SPIs) > 0 {
		spiSize = len(d.SPIs[0])
	}
	b := make([]byte, 4, 4+spiSize*len(d.SPIs))
	b[0] = byte(d.Protocol)
	b[1] = byte(spiSize)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(d.SPIs)))
	for _, s := range d.SPIs {
		b = append(b, s...)
	}
	return b
}

func DecodeDelete(body []byte) (Delete, error) {
	if len(body) < 4 {
		return Delete{}, fmt.Errorf("ike: short delete payload")
	}
	spiSize, count := int(body[1]), int(binary.BigEndian.Uint16(body[2:4]))
	if len(body) != 4+spiSize*count {
		return Delete{}, fmt.Errorf("ike: invalid delete payload length")
	}
	d := Delete{Protocol: ProtocolID(body[0])}
	for rest := body[4:]; len(rest) > 0; rest = rest[spiSize:] {
		d.SPIs = append(d.SPIs, append([]byte(nil), rest[:spiSize]...))
	}
	return d, nil
}

// --- Identification payload, RFC 7296 §3.5 ---

func EncodeID(idType uint8, data []byte) []byte {
	b := make([]byte, 4+len(data))
	b[0] = idType
	copy(b[4:], data)
	return b
}

func DecodeID(body []byte) (idType uint8, data []byte, err error) {
	if len(body) < 4 {
		return 0, nil, fmt.Errorf("ike: short ID payload")
	}
	return body[0], body[4:], nil
}

// --- Traffic Selector payload, RFC 7296 §3.13 ---

const (
	TS_IPV4_ADDR_RANGE uint8 = 7
	TS_IPV6_ADDR_RANGE uint8 = 8
)

type TrafficSelector struct {
	Type      uint8
	Protocol  uint8 // 0 = any
	StartPort uint16
	EndPort   uint16
	StartAddr net.IP
	EndAddr   net.IP
}

// FullRangeV4 / FullRangeV6 are the 0.0.0.0/0 and ::/0 selectors ranet
// configures for every child SA (tunnel mode, no per-node subnetting).
func FullRangeV4() TrafficSelector {
	return TrafficSelector{Type: TS_IPV4_ADDR_RANGE, EndPort: 0xffff,
		StartAddr: net.IPv4zero.To4(), EndAddr: net.IPv4(255, 255, 255, 255).To4()}
}

func FullRangeV6() TrafficSelector {
	return TrafficSelector{Type: TS_IPV6_ADDR_RANGE, EndPort: 0xffff,
		StartAddr: net.IPv6zero, EndAddr: net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}
}

func (ts TrafficSelector) encode() []byte {
	addr := ts.StartAddr.To4()
	if ts.Type == TS_IPV6_ADDR_RANGE {
		addr = ts.StartAddr.To16()
	}
	alen := len(addr)
	b := make([]byte, 8+2*alen)
	b[0] = ts.Type
	b[1] = ts.Protocol
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:6], ts.StartPort)
	binary.BigEndian.PutUint16(b[6:8], ts.EndPort)
	copy(b[8:8+alen], addr)
	end := ts.EndAddr.To4()
	if ts.Type == TS_IPV6_ADDR_RANGE {
		end = ts.EndAddr.To16()
	}
	copy(b[8+alen:], end)
	return b
}

func EncodeTS(selectors []TrafficSelector) []byte {
	b := []byte{byte(len(selectors)), 0, 0, 0}
	for _, ts := range selectors {
		b = append(b, ts.encode()...)
	}
	return b
}

func DecodeTS(body []byte) ([]TrafficSelector, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("ike: short TS payload")
	}
	count := int(body[0])
	rest := body[4:]
	var out []TrafficSelector
	for i := 0; i < count; i++ {
		if len(rest) < 8 {
			return nil, fmt.Errorf("ike: truncated traffic selector")
		}
		tlen := binary.BigEndian.Uint16(rest[2:4])
		if tlen < 8 || int(tlen) > len(rest) || (tlen-8)%2 != 0 {
			return nil, fmt.Errorf("ike: invalid TS length")
		}
		ts := TrafficSelector{
			Type:      rest[0],
			Protocol:  rest[1],
			StartPort: binary.BigEndian.Uint16(rest[4:6]),
			EndPort:   binary.BigEndian.Uint16(rest[6:8]),
		}
		alen := (int(tlen) - 8) / 2
		ts.StartAddr = append([]byte{}, rest[8:8+alen]...)
		ts.EndAddr = append([]byte{}, rest[8+alen:8+2*alen]...)
		out = append(out, ts)
		rest = rest[tlen:]
	}
	return out, nil
}
