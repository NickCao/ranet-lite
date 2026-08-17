package babel

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Hello is RFC 8966 §4.6.4. On our topology every peer is its own
// point-to-point link (a separate ESP tunnel), so we always set the
// Unicast flag (§4.6.4 "Unicast Hello") — there is no shared segment to
// multicast on.
type Hello struct {
	Seqno    uint16
	Interval uint16 // centiseconds
	TSTx     uint32 // RFC 9616 Timestamp sub-TLV; 0 if omitted
	HasTS    bool
}

func EncodeHello(h Hello) RawTLV {
	body := make([]byte, 6)
	binary.BigEndian.PutUint16(body[0:2], HelloFlagUnicast)
	binary.BigEndian.PutUint16(body[2:4], h.Seqno)
	binary.BigEndian.PutUint16(body[4:6], h.Interval)
	if h.HasTS {
		ts := make([]byte, 4)
		binary.BigEndian.PutUint32(ts, h.TSTx)
		body = append(body, encodeSubTLVs([]SubTLV{{Type: SubTLVTimestamp, Body: ts}})...)
	}
	return RawTLV{Type: TLVHello, Body: body}
}

func DecodeHello(body []byte) (Hello, error) {
	if len(body) < 6 {
		return Hello{}, fmt.Errorf("babel: short Hello TLV")
	}
	h := Hello{
		Seqno:    binary.BigEndian.Uint16(body[2:4]),
		Interval: binary.BigEndian.Uint16(body[4:6]),
	}
	subs := decodeSubTLVs(body[6:])
	if ts, ok := findSubTLV(subs, SubTLVTimestamp); ok && len(ts) >= 4 {
		h.TSTx = binary.BigEndian.Uint32(ts)
		h.HasTS = true
	}
	return h, nil
}

// IHU ("I Heard You") is RFC 8966 §4.6.5. AE=Wildcard omits the address
// entirely, valid "only on point-to-point links" per spec — exactly our
// per-peer tunnel model, so we always use it.
type IHU struct {
	RxCost   uint16
	Interval uint16 // centiseconds
	TSTx     uint32 // this IHU sender's own clock, for the reverse RTT measurement
	TSOrigin uint32 // echoes the Hello's TS_TX, RFC 9616
	HasTS    bool
}

func EncodeIHU(ihu IHU) RawTLV {
	body := make([]byte, 6)
	body[0] = AEWildcard
	binary.BigEndian.PutUint16(body[2:4], ihu.RxCost)
	binary.BigEndian.PutUint16(body[4:6], ihu.Interval)
	if ihu.HasTS {
		ts := make([]byte, 8)
		binary.BigEndian.PutUint32(ts[0:4], ihu.TSTx)
		binary.BigEndian.PutUint32(ts[4:8], ihu.TSOrigin)
		body = append(body, encodeSubTLVs([]SubTLV{{Type: SubTLVTimestamp, Body: ts}})...)
	}
	return RawTLV{Type: TLVIHU, Body: body}
}

func DecodeIHU(body []byte) (IHU, net.IP, error) {
	if len(body) < 6 {
		return IHU{}, nil, fmt.Errorf("babel: short IHU TLV")
	}
	ae := body[0]
	ihu := IHU{
		RxCost:   binary.BigEndian.Uint16(body[2:4]),
		Interval: binary.BigEndian.Uint16(body[4:6]),
	}
	rest := body[6:]
	var addr net.IP
	if ae != AEWildcard {
		a, err := decodeAddress(ae, rest)
		if err != nil {
			return IHU{}, nil, err
		}
		addr = a
		alen := 4
		if ae == AEIPv6 {
			alen = 16
		} else if ae == AEIPv6LinkLocal {
			alen = 8
		}
		rest = rest[alen:]
	}
	subs := decodeSubTLVs(rest)
	if ts, ok := findSubTLV(subs, SubTLVTimestamp); ok && len(ts) >= 8 {
		ihu.TSTx = binary.BigEndian.Uint32(ts[0:4])
		ihu.TSOrigin = binary.BigEndian.Uint32(ts[4:8])
		ihu.HasTS = true
	}
	return ihu, addr, nil
}
