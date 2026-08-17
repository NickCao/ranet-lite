package babel

import (
	"encoding/binary"
	"fmt"
	"net"
)

// RawTLV is an undecoded TLV: Type + Body (excluding the 2-byte Type/Length
// header). Pad1/PadN carry no useful body and are skipped transparently by
// EncodePacket/DecodePacket.
type RawTLV struct {
	Type TLVType
	Body []byte
}

// EncodePacket frames a Babel packet: 4-byte header + concatenated TLVs.
func EncodePacket(tlvs []RawTLV) []byte {
	body := make([]byte, 0, 128)
	for _, t := range tlvs {
		if t.Type == TLVPad1 {
			// Pad1 is the one TLV with no Length field, RFC 8966 §4.6.1 —
			// it's a single 0x00 byte, not Type+Length+Body.
			body = append(body, byte(TLVPad1))
			continue
		}
		body = append(body, byte(t.Type), byte(len(t.Body)))
		body = append(body, t.Body...)
	}
	out := make([]byte, headerLen+len(body))
	out[0] = Magic
	out[1] = Version
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)))
	copy(out[headerLen:], body)
	return out
}

// DecodePacket validates the header and splits the body into TLVs.
// Pad1/PadN are dropped (they carry no information); everything else is
// returned as-is for the caller to interpret.
func DecodePacket(b []byte) ([]RawTLV, error) {
	if len(b) < headerLen {
		return nil, fmt.Errorf("babel: short packet (%d bytes)", len(b))
	}
	if b[0] != Magic {
		return nil, fmt.Errorf("babel: bad magic %d", b[0])
	}
	// Version is not checked strictly: RFC 8966 §4.2 says implementations
	// MUST ignore packets with an unknown version in the *TLV* sense only
	// if they can't parse it; since our TLV framing is version-independent
	// so far, we just proceed.
	bodyLen := binary.BigEndian.Uint16(b[2:4])
	if int(headerLen)+int(bodyLen) > len(b) {
		return nil, fmt.Errorf("babel: body length %d exceeds packet size", bodyLen)
	}
	body := b[headerLen : headerLen+int(bodyLen)]

	var out []RawTLV
	for len(body) > 0 {
		t := TLVType(body[0])
		if t == TLVPad1 {
			body = body[1:]
			continue
		}
		if len(body) < 2 {
			return nil, fmt.Errorf("babel: truncated TLV header")
		}
		l := int(body[1])
		if 2+l > len(body) {
			return nil, fmt.Errorf("babel: TLV type %d length %d exceeds packet", t, l)
		}
		if t != TLVPadN {
			out = append(out, RawTLV{Type: t, Body: append([]byte{}, body[2:2+l]...)})
		}
		body = body[2+l:]
	}
	return out, nil
}

// --- sub-TLVs (trailing content of Hello/IHU/Update TLVs) ---

type SubTLV struct {
	Type uint8
	Body []byte
}

func encodeSubTLVs(subs []SubTLV) []byte {
	var out []byte
	for _, s := range subs {
		out = append(out, s.Type, byte(len(s.Body)))
		out = append(out, s.Body...)
	}
	return out
}

func decodeSubTLVs(b []byte) []SubTLV {
	var out []SubTLV
	for len(b) > 0 {
		if b[0] == SubTLVPad1 {
			b = b[1:]
			continue
		}
		if len(b) < 2 {
			return out // truncated trailer: ignore rather than fail the whole TLV
		}
		l := int(b[1])
		if 2+l > len(b) {
			return out
		}
		if b[0] != SubTLVPadN {
			out = append(out, SubTLV{Type: b[0], Body: append([]byte{}, b[2:2+l]...)})
		}
		b = b[2+l:]
	}
	return out
}

func findSubTLV(subs []SubTLV, t uint8) ([]byte, bool) {
	for _, s := range subs {
		if s.Type == t {
			return s.Body, true
		}
	}
	return nil, false
}

// --- full-length address encoding (Hello has none; IHU/NextHop use this) ---

func encodeAddress(addr net.IP) (ae uint8, body []byte) {
	if v4 := addr.To4(); v4 != nil {
		return AEIPv4, v4
	}
	return AEIPv6, addr.To16()
}

func decodeAddress(ae uint8, body []byte) (net.IP, error) {
	switch ae {
	case AEIPv4:
		if len(body) < 4 {
			return nil, fmt.Errorf("babel: short IPv4 address")
		}
		return net.IP(body[:4]), nil
	case AEIPv6:
		if len(body) < 16 {
			return nil, fmt.Errorf("babel: short IPv6 address")
		}
		return net.IP(body[:16]), nil
	case AEIPv6LinkLocal:
		if len(body) < 8 {
			return nil, fmt.Errorf("babel: short IPv6 link-local address")
		}
		ip := make(net.IP, 16)
		ip[0], ip[1] = 0xfe, 0x80
		copy(ip[8:], body[:8])
		return ip, nil
	default:
		return nil, fmt.Errorf("babel: unsupported address encoding %d", ae)
	}
}
