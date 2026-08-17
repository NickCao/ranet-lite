package babel

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Hello is RFC 8966 §4.6.4. We always send what the RFC calls a
// "Multicast Hello" (Unicast flag clear) — a slight misnomer, since it's
// delivered as one packet per neighbor over each point-to-point ESP
// tunnel, not literally multicast on the wire. The classification matters
// because implementations (e.g. BIRD) track Multicast- and Unicast-Hello
// sequence numbers/loss-history in separate buckets per RFC 8966 §3.2.4;
// setting the Unicast flag while actually delivering to the standard
// multicast destination address (which our peers, like BIRD, listen on
// regardless) puts us in the wrong bucket and the Hello is never counted.
type Hello struct {
	Seqno    uint16
	Interval uint16 // centiseconds
	TxTS     uint32 // RFC 9616 §6.1 Transmit Timestamp (microseconds, arbitrary origin); 0 if omitted
	HasTS    bool
}

func EncodeHello(h Hello) RawTLV {
	body := make([]byte, 6)
	// Flags left at 0: this is a "Multicast Hello" per RFC 8966 §3.2.4's
	// classification (see the Hello doc comment above) — the Unicast flag
	// is deliberately never set.
	binary.BigEndian.PutUint16(body[2:4], h.Seqno)
	binary.BigEndian.PutUint16(body[4:6], h.Interval)
	if h.HasTS {
		ts := make([]byte, 4)
		binary.BigEndian.PutUint32(ts, h.TxTS)
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
		h.TxTS = binary.BigEndian.Uint32(ts)
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
	// OriginTS/ReceiveTS are RFC 9616 §6.2: a copy of the Transmit
	// Timestamp from the last timestamped Hello we received from this
	// neighbor, and our own clock's reading at the moment we received it
	// — NOT "now" (the time we're sending this IHU). The asymmetry is the
	// whole point: it lets the original sender subtract our processing
	// delay out of its RTT estimate.
	OriginTS  uint32
	ReceiveTS uint32
	HasTS     bool
}

func EncodeIHU(ihu IHU) RawTLV {
	body := make([]byte, 6)
	body[0] = AEWildcard
	binary.BigEndian.PutUint16(body[2:4], ihu.RxCost)
	binary.BigEndian.PutUint16(body[4:6], ihu.Interval)
	if ihu.HasTS {
		ts := make([]byte, 8)
		binary.BigEndian.PutUint32(ts[0:4], ihu.OriginTS)
		binary.BigEndian.PutUint32(ts[4:8], ihu.ReceiveTS)
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
		ihu.OriginTS = binary.BigEndian.Uint32(ts[0:4])
		ihu.ReceiveTS = binary.BigEndian.Uint32(ts[4:8])
		ihu.HasTS = true
	}
	return ihu, addr, nil
}
