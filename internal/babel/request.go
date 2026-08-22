package babel

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

type RouteRequest struct {
	AE     uint8
	Prefix netip.Prefix
}

func EncodeRouteRequest(r RouteRequest) RawTLV {
	if r.AE == AEWildcard || !r.Prefix.IsValid() {
		return RawTLV{Type: TLVRouteRequest, Body: []byte{AEWildcard, 0}}
	}
	p := r.Prefix.Masked()
	raw := p.Addr().AsSlice()
	return RawTLV{Type: TLVRouteRequest, Body: append([]byte{r.AE, byte(p.Bits())}, raw[:prefixByteLen(p.Bits())]...)}
}

func DecodeRouteRequest(body []byte) (RouteRequest, error) {
	if len(body) < 2 {
		return RouteRequest{}, fmt.Errorf("babel: short Route Request TLV")
	}
	return decodeRequestPrefix(body[0], int(body[1]), body[2:], RouteRequest{AE: body[0]})
}

func decodeRequestPrefix(ae uint8, plen int, raw []byte, out RouteRequest) (RouteRequest, error) {
	if ae == AEWildcard {
		if plen != 0 {
			return RouteRequest{}, fmt.Errorf("babel: wildcard request has nonzero prefix length")
		}
		return out, nil
	}
	bits := 128
	if ae == AEIPv4 {
		bits = 32
	} else if ae != AEIPv6 {
		return RouteRequest{}, fmt.Errorf("babel: request has unsupported AE %d", ae)
	}
	if plen > bits || len(raw) < prefixByteLen(plen) {
		return RouteRequest{}, fmt.Errorf("babel: malformed request prefix")
	}
	buf := make([]byte, bits/8)
	copy(buf, raw[:prefixByteLen(plen)])
	addr, _ := netip.AddrFromSlice(net.IP(buf))
	out.Prefix = netip.PrefixFrom(addr.Unmap(), plen).Masked()
	return out, nil
}

type SeqnoRequest struct {
	AE       uint8
	Prefix   netip.Prefix
	Seqno    uint16
	HopCount uint8
	RouterID [8]byte
}

func EncodeSeqnoRequest(r SeqnoRequest) RawTLV {
	p := r.Prefix.Masked()
	raw := p.Addr().AsSlice()
	body := make([]byte, 14, 14+prefixByteLen(p.Bits()))
	body[0], body[1] = r.AE, byte(p.Bits())
	binary.BigEndian.PutUint16(body[2:4], r.Seqno)
	body[4] = r.HopCount
	copy(body[6:14], r.RouterID[:])
	body = append(body, raw[:prefixByteLen(p.Bits())]...)
	return RawTLV{Type: TLVSeqnoRequest, Body: body}
}

func DecodeSeqnoRequest(body []byte) (SeqnoRequest, error) {
	if len(body) < 14 {
		return SeqnoRequest{}, fmt.Errorf("babel: short Seqno Request TLV")
	}
	base, err := decodeRequestPrefix(body[0], int(body[1]), body[14:], RouteRequest{AE: body[0]})
	if err != nil {
		return SeqnoRequest{}, fmt.Errorf("babel: malformed Seqno Request TLV: %w", err)
	}
	if !base.Prefix.IsValid() {
		return SeqnoRequest{}, fmt.Errorf("babel: malformed Seqno Request TLV prefix")
	}
	r := SeqnoRequest{AE: body[0], Prefix: base.Prefix, Seqno: binary.BigEndian.Uint16(body[2:4]), HopCount: body[4]}
	copy(r.RouterID[:], body[6:14])
	return r, nil
}
