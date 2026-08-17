package babel

import (
	"encoding/binary"
	"fmt"
	"net"
)

// RouterID TLV, RFC 8966 §4.6.7: Reserved(2) + 8-byte Router-Id.
func EncodeRouterID(id [8]byte) RawTLV {
	body := make([]byte, 10)
	copy(body[2:], id[:])
	return RawTLV{Type: TLVRouterID, Body: body}
}

func DecodeRouterID(body []byte) ([8]byte, error) {
	var id [8]byte
	if len(body) < 10 {
		return id, fmt.Errorf("babel: short Router-Id TLV")
	}
	copy(id[:], body[2:10])
	return id, nil
}

// NextHop TLV, RFC 8966 §4.6.8.
func EncodeNextHop(addr net.IP) RawTLV {
	ae, a := encodeAddress(addr)
	body := make([]byte, 2+len(a))
	body[0] = ae
	copy(body[2:], a)
	return RawTLV{Type: TLVNextHop, Body: body}
}

func DecodeNextHop(body []byte) (net.IP, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("babel: short NextHop TLV")
	}
	return decodeAddress(body[0], body[2:])
}

// AckReq / Ack, RFC 8966 §4.6.2/§4.6.3 — used for reliable signaling of
// e.g. link-down Updates. We answer AckReq (being unresponsive would make
// us a badly behaved peer) but don't originate AckReq ourselves in this
// minimal speaker.
func EncodeAckReq(nonce uint16, interval uint16) RawTLV {
	body := make([]byte, 6)
	binary.BigEndian.PutUint16(body[2:4], nonce)
	binary.BigEndian.PutUint16(body[4:6], interval)
	return RawTLV{Type: TLVAckReq, Body: body}
}

func DecodeAckReq(body []byte) (nonce uint16, err error) {
	if len(body) < 4 {
		return 0, fmt.Errorf("babel: short AckReq TLV")
	}
	return binary.BigEndian.Uint16(body[2:4]), nil
}

func EncodeAck(nonce uint16) RawTLV {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, nonce)
	return RawTLV{Type: TLVAck, Body: body}
}
