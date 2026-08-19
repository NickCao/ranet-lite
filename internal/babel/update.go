package babel

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

// SubTLVSourcePrefix carries a source prefix for source-specific routing
// (draft-ietf-babel-source-specific, a.k.a. SADR — Source Address
// Dependent Routing; real deployments send this from e.g. BIRD's "ipv6
// sadr" tables). Its type is 128, the first mandatory sub-TLV value (RFC
// 8966 §4.4: types 128-255 have the mandatory bit set), so an
// implementation that doesn't recognize it MUST ignore the whole
// enclosing TLV rather than silently treat it as an ordinary route.
const SubTLVSourcePrefix uint8 = 128

const (
	updateFlagPrefix   = 0x80
	updateFlagRouterID = 0x40
)

// Update is RFC 8966 §4.6.9. We always encode with Omitted=0 (no prefix
// compression) — that's fully spec-compliant, compression is a size
// optimization a receiver must support but a sender need not use. We do
// decode compressed prefixes from peers (e.g. BIRD announcing several
// prefixes in one packet), via PrefixDecoder.
type Update struct {
	AE       uint8
	Plen     int
	Interval uint16 // centiseconds
	Seqno    uint16
	Metric   uint16 // MetricInfinity means "route retracted"
	Prefix   net.IP

	// Ignore is set when this Update carries a sub-TLV with the mandatory
	// bit set (type 128-255, RFC 8966 §4.4) that we don't recognize at
	// all (i.e. anything other than Source Prefix, or a malformed Source
	// Prefix). The whole TLV must be ignored per spec — but the
	// compression state above must still be updated from it, which is why
	// this is a flag on a fully-decoded Update rather than a decode error.
	Ignore bool

	// SourcePrefix is set when this Update carries a well-formed Source
	// Prefix sub-TLV (source-specific routing). We don't implement a full
	// source-and-destination-keyed route table; the special case we do
	// support (see Speaker) is installing it as an ordinary route exactly
	// when SourcePrefix covers our own outbound source address — i.e.
	// "this route applies to traffic we'd actually originate" — and
	// ignoring it otherwise.
	SourcePrefix netip.Prefix
}

func prefixByteLen(plen int) int { return (plen + 7) / 8 }

func EncodeUpdate(u Update) RawTLV {
	total := prefixByteLen(u.Plen)
	var raw []byte
	switch u.AE {
	case AEIPv4:
		raw = u.Prefix.To4()
	case AEIPv6:
		raw = u.Prefix.To16()
	default:
		panic("babel: EncodeUpdate: unsupported AE")
	}
	body := make([]byte, 10+total)
	body[0] = u.AE
	body[1] = updateFlagPrefix
	body[2] = byte(u.Plen)
	body[3] = 0 // Omitted
	binary.BigEndian.PutUint16(body[4:6], u.Interval)
	binary.BigEndian.PutUint16(body[6:8], u.Seqno)
	binary.BigEndian.PutUint16(body[8:10], u.Metric)
	copy(body[10:], raw[:total])
	return RawTLV{Type: TLVUpdate, Body: body}
}

// PrefixDecoder holds the per-packet compression state RFC 8966 §4.6.9
// requires: each Update's Omitted bytes refer to the previous prefix *of
// the same address family sent within this packet*. Create one per
// incoming packet, not one per neighbor.
type PrefixDecoder struct {
	lastV4 [4]byte
	lastV6 [16]byte
	haveV4 bool
	haveV6 bool
}

func (d *PrefixDecoder) Decode(body []byte) (Update, error) {
	if len(body) < 10 {
		return Update{}, fmt.Errorf("babel: short Update TLV")
	}
	ae := body[0]
	flags := body[1]
	plen := int(body[2])
	omitted := int(body[3])
	interval := binary.BigEndian.Uint16(body[4:6])
	seqno := binary.BigEndian.Uint16(body[6:8])
	metric := binary.BigEndian.Uint16(body[8:10])
	sent := body[10:]

	switch ae {
	case AEWildcard:
		if plen != 0 || omitted != 0 {
			return Update{}, fmt.Errorf("babel: wildcard Update has a nonzero prefix length")
		}
	case AEIPv4:
		if plen > 32 {
			return Update{}, fmt.Errorf("babel: IPv4 Update prefix length %d exceeds 32", plen)
		}
		if omitted > 0 && !d.haveV4 {
			return Update{}, fmt.Errorf("babel: compressed IPv4 Update has no default prefix")
		}
	case AEIPv6:
		if plen > 128 {
			return Update{}, fmt.Errorf("babel: IPv6 Update prefix length %d exceeds 128", plen)
		}
		if omitted > 0 && !d.haveV6 {
			return Update{}, fmt.Errorf("babel: compressed IPv6 Update has no default prefix")
		}
	default:
		return Update{}, fmt.Errorf("babel: Update: unsupported AE %d", ae)
	}
	total := prefixByteLen(plen)
	if omitted > total {
		return Update{}, fmt.Errorf("babel: Update Omitted %d exceeds prefix length", omitted)
	}
	sentLen := total - omitted
	if len(sent) < sentLen {
		return Update{}, fmt.Errorf("babel: Update prefix truncated")
	}

	var ip net.IP
	switch ae {
	case AEWildcard:
		// A Wildcard-AE Update with Plen 0 is a "route retraction for all
		// prefixes" marker in some implementations' keepalive behavior;
		// we don't originate it, but tolerate it as an empty/no-op prefix.
		ip = net.IPv4zero
	case AEIPv4:
		buf := make([]byte, 4)
		copy(buf, d.lastV4[:omitted])
		copy(buf[omitted:], sent[:sentLen])
		if flags&updateFlagPrefix != 0 {
			d.lastV4, d.haveV4 = [4]byte(buf), true
		}
		ip = net.IPv4(buf[0], buf[1], buf[2], buf[3])
	case AEIPv6:
		buf := make([]byte, 16)
		copy(buf, d.lastV6[:omitted])
		copy(buf[omitted:], sent[:sentLen])
		if flags&updateFlagPrefix != 0 {
			d.lastV6, d.haveV6 = [16]byte(buf), true
		}
		ip = net.IP(buf)
	}

	u := Update{AE: ae, Plen: plen, Interval: interval, Seqno: seqno, Metric: metric, Prefix: ip}
	if flags&updateFlagRouterID != 0 || flags & ^uint8(updateFlagPrefix|updateFlagRouterID) != 0 {
		u.Ignore = true
	}
	if ae == AEWildcard && metric != MetricInfinity {
		u.Ignore = true
	}
	subs, err := decodeSubTLVs(sent[sentLen:])
	if err != nil {
		u.Ignore = true
		return u, nil
	}
	sourcePrefixes := 0
	for _, s := range subs {
		if s.Type < 128 {
			continue // non-mandatory: safe to skip if unrecognized
		}
		if s.Type != SubTLVSourcePrefix {
			u.Ignore = true // some other mandatory sub-TLV we don't understand at all
			continue
		}
		sourcePrefixes++
		if sourcePrefixes > 1 {
			u.Ignore = true
			continue
		}
		if sp, ok := decodeSourcePrefix(ae, s.Body); ok {
			u.SourcePrefix = sp
		} else {
			u.Ignore = true // present but malformed — RFC 8966 §4.4 treats this the same as unrecognized
		}
	}
	return u, nil
}

// decodeSourcePrefix parses a Source Prefix sub-TLV body (draft-ietf-babel
// -source-specific §7.1): SourcePlen(1) + SourcePrefix bytes, ceil(plen/8)
// of them, uncompressed, interpreted under the enclosing TLV's AE.
func decodeSourcePrefix(ae uint8, body []byte) (netip.Prefix, bool) {
	if len(body) < 1 {
		return netip.Prefix{}, false
	}
	plen := int(body[0])
	if plen == 0 {
		return netip.Prefix{}, false // "This MUST NOT be 0" — treat a violation as malformed
	}
	n := prefixByteLen(plen)
	if len(body)-1 < n {
		return netip.Prefix{}, false
	}
	raw := body[1 : 1+n]
	switch ae {
	case AEIPv4:
		if plen > 32 {
			return netip.Prefix{}, false
		}
		var buf [4]byte
		copy(buf[:], raw)
		return netip.PrefixFrom(netip.AddrFrom4(buf), plen).Masked(), true
	case AEIPv6:
		if plen > 128 {
			return netip.Prefix{}, false
		}
		var buf [16]byte
		copy(buf[:], raw)
		return netip.PrefixFrom(netip.AddrFrom16(buf), plen).Masked(), true
	default:
		return netip.Prefix{}, false
	}
}
