package babel

import (
	"encoding/binary"
	"fmt"
	"net"
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
	body[1] = 0 // Flags: reserved, MUST be sent as 0
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
}

func (d *PrefixDecoder) Decode(body []byte) (Update, error) {
	if len(body) < 10 {
		return Update{}, fmt.Errorf("babel: short Update TLV")
	}
	ae := body[0]
	plen := int(body[2])
	omitted := int(body[3])
	interval := binary.BigEndian.Uint16(body[4:6])
	seqno := binary.BigEndian.Uint16(body[6:8])
	metric := binary.BigEndian.Uint16(body[8:10])
	sent := body[10:]

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
		d.lastV4 = [4]byte(buf)
		ip = net.IPv4(buf[0], buf[1], buf[2], buf[3])
	case AEIPv6:
		buf := make([]byte, 16)
		copy(buf, d.lastV6[:omitted])
		copy(buf[omitted:], sent[:sentLen])
		d.lastV6 = [16]byte(buf)
		ip = net.IP(buf)
	default:
		return Update{}, fmt.Errorf("babel: Update: unsupported AE %d", ae)
	}

	return Update{AE: ae, Plen: plen, Interval: interval, Seqno: seqno, Metric: metric, Prefix: ip}, nil
}
