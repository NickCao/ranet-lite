package ike

import (
	"encoding/binary"
	"fmt"
)

// Transform is one Transform substructure of a Proposal, RFC 7296 §3.3.2.
type Transform struct {
	Type          TransformType
	ID            uint16
	KeyLengthBits uint16 // 0 => no Key Length attribute
}

func (t Transform) encode(last bool) []byte {
	lastByte := byte(3)
	if last {
		lastByte = 0
	}
	var attrs []byte
	if t.KeyLengthBits != 0 {
		attrs = make([]byte, 4)
		binary.BigEndian.PutUint16(attrs[0:2], 0x8000|AttrKeyLength)
		binary.BigEndian.PutUint16(attrs[2:4], t.KeyLengthBits)
	}
	b := make([]byte, 8+len(attrs))
	b[0] = lastByte
	binary.BigEndian.PutUint16(b[2:4], uint16(8+len(attrs)))
	b[4] = byte(t.Type)
	binary.BigEndian.PutUint16(b[6:8], t.ID)
	copy(b[8:], attrs)
	return b
}

func decodeTransform(b []byte) (Transform, bool, []byte, error) {
	if len(b) < 8 {
		return Transform{}, false, nil, fmt.Errorf("ike: short transform")
	}
	more := b[0] == 3
	tlen := binary.BigEndian.Uint16(b[2:4])
	if int(tlen) < 8 || int(tlen) > len(b) {
		return Transform{}, false, nil, fmt.Errorf("ike: invalid transform length %d", tlen)
	}
	t := Transform{
		Type: TransformType(b[4]),
		ID:   binary.BigEndian.Uint16(b[6:8]),
	}
	attrs := b[8:tlen]
	for len(attrs) >= 4 {
		at := binary.BigEndian.Uint16(attrs[0:2])
		av := binary.BigEndian.Uint16(attrs[2:4])
		if at&0x8000 != 0 && (at&0x7fff) == AttrKeyLength {
			t.KeyLengthBits = av
		}
		attrs = attrs[4:] // all attributes we care about are TV-format (4 bytes)
	}
	return t, more, b[tlen:], nil
}

// Proposal is one Proposal substructure of an SA payload, RFC 7296 §3.3.1.
type Proposal struct {
	Number     uint8
	Protocol   ProtocolID
	SPI        []byte
	Transforms []Transform
}

func (p Proposal) encode(last bool) []byte {
	var tbody []byte
	for i, t := range p.Transforms {
		tbody = append(tbody, t.encode(i == len(p.Transforms)-1)...)
	}
	lastByte := byte(2)
	if last {
		lastByte = 0
	}
	hdrLen := 8 + len(p.SPI)
	b := make([]byte, hdrLen+len(tbody))
	b[0] = lastByte
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[4] = p.Number
	b[5] = byte(p.Protocol)
	b[6] = byte(len(p.SPI))
	b[7] = byte(len(p.Transforms))
	copy(b[8:], p.SPI)
	copy(b[hdrLen:], tbody)
	return b
}

func decodeProposal(b []byte) (Proposal, bool, []byte, error) {
	if len(b) < 8 {
		return Proposal{}, false, nil, fmt.Errorf("ike: short proposal")
	}
	more := b[0] == 2
	plen := binary.BigEndian.Uint16(b[2:4])
	if int(plen) < 8 || int(plen) > len(b) {
		return Proposal{}, false, nil, fmt.Errorf("ike: invalid proposal length %d", plen)
	}
	p := Proposal{
		Number:   b[4],
		Protocol: ProtocolID(b[5]),
	}
	spiSize := int(b[6])
	numTrans := int(b[7])
	rest := b[8:plen]
	if len(rest) < spiSize {
		return Proposal{}, false, nil, fmt.Errorf("ike: proposal SPI truncated")
	}
	p.SPI = append([]byte{}, rest[:spiSize]...)
	rest = rest[spiSize:]
	for i := 0; i < numTrans; i++ {
		t, more, next, err := decodeTransform(rest)
		if err != nil {
			return Proposal{}, false, nil, err
		}
		p.Transforms = append(p.Transforms, t)
		rest = next
		if !more {
			break
		}
	}
	return p, more, b[plen:], nil
}

// EncodeSA builds an SA payload body from an ordered list of proposals.
func EncodeSA(proposals []Proposal) []byte {
	var out []byte
	for i, p := range proposals {
		out = append(out, p.encode(i == len(proposals)-1)...)
	}
	return out
}

// DecodeSA parses an SA payload body into its proposals.
func DecodeSA(body []byte) ([]Proposal, error) {
	var props []Proposal
	rest := body
	for len(rest) > 0 {
		p, more, next, err := decodeProposal(rest)
		if err != nil {
			return nil, err
		}
		props = append(props, p)
		rest = next
		if !more {
			break
		}
	}
	return props, nil
}

// ChosenTransform returns the single transform of the given type from a
// (already-selected, single-proposal) SA payload, as returned by a
// well-behaved IKEv2 responder.
func (p Proposal) ChosenTransform(t TransformType) (Transform, bool) {
	for _, tr := range p.Transforms {
		if tr.Type == t {
			return tr, true
		}
	}
	return Transform{}, false
}
