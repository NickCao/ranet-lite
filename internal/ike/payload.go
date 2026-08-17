package ike

import (
	"encoding/binary"
	"fmt"
)

// genericPayloadHeaderLen is the size of the Next Payload / Critical+Reserved
// / Payload Length fields shared by every payload, RFC 7296 §3.2.
const genericPayloadHeaderLen = 4

// RawPayload is an undecoded IKE payload: a type tag plus its body bytes
// (the body does not include the generic 4-byte payload header).
type RawPayload struct {
	Type     PayloadType
	Critical bool
	Body     []byte
}

// Message is a full IKEv2 message: header plus an ordered list of payloads.
// The payload chain (Next Payload pointers) is derived from ordering on
// Encode and walked automatically on Decode.
type Message struct {
	Header   Header
	Payloads []RawPayload

	// skHeaderOffset is the byte offset (from the start of the decoded
	// message) of the SK payload's generic header, set only when the last
	// decoded payload is PayloadSK. It lets DecryptSK reconstruct the exact
	// AAD (RFC 5282 §3.1: header + cleartext payloads + SK generic header)
	// without re-encoding anything.
	skHeaderOffset int
}

// Encode serializes the message. It does not encrypt; callers that need an
// SK payload must pre-build it (see sk.go) and pass it as the sole payload
// after the header's cleartext payloads, i.e. call EncodeWithFirstNext with
// PayloadSK as the first payload type when there's exactly one SK payload.
func (m *Message) Encode() []byte {
	return m.encode(0)
}

func (m *Message) encode(reserveTrailer int) []byte {
	body := encodePayloadChain(m.Payloads)
	firstType := PayloadNone
	if len(m.Payloads) > 0 {
		firstType = m.Payloads[0].Type
	}
	h := m.Header
	h.NextPayload = firstType
	h.Length = uint32(HeaderLen + len(body) + reserveTrailer)
	out := make([]byte, 0, HeaderLen+len(body))
	out = append(out, h.encode()...)
	out = append(out, body...)
	return out
}

// encodePayloadChain serializes a list of payloads with Next Payload
// pointers chained in order; shared by Message.encode and the SK payload's
// inner-plaintext construction (sk.go).
func encodePayloadChain(payloads []RawPayload) []byte {
	body := make([]byte, 0, 256)
	for i, p := range payloads {
		next := PayloadNone
		if i+1 < len(payloads) {
			next = payloads[i+1].Type
		}
		hdr := make([]byte, genericPayloadHeaderLen)
		hdr[0] = byte(next)
		if p.Critical {
			hdr[1] = 0x80
		}
		binary.BigEndian.PutUint16(hdr[2:4], uint16(genericPayloadHeaderLen+len(p.Body)))
		body = append(body, hdr...)
		body = append(body, p.Body...)
	}
	return body
}

// decodePayloadChain walks a Next-Payload chain within a flat byte slice
// (used to parse the decrypted contents of an SK payload).
func decodePayloadChain(first PayloadType, b []byte) ([]RawPayload, error) {
	var out []RawPayload
	next := first
	rest := b
	for next != PayloadNone {
		if len(rest) < genericPayloadHeaderLen {
			return nil, fmt.Errorf("ike: truncated payload header")
		}
		plLen := binary.BigEndian.Uint16(rest[2:4])
		if int(plLen) < genericPayloadHeaderLen || int(plLen) > len(rest) {
			return nil, fmt.Errorf("ike: invalid payload length %d", plLen)
		}
		out = append(out, RawPayload{
			Type:     next,
			Critical: rest[1]&0x80 != 0,
			Body:     rest[genericPayloadHeaderLen:plLen],
		})
		next = PayloadType(rest[0])
		rest = rest[plLen:]
	}
	return out, nil
}

// DecodeMessage parses an IKE header and walks its payload chain. It does
// not decrypt SK payloads — the SK payload, if present, is returned as a
// single RawPayload{Type: PayloadSK} whose Body is the encrypted blob
// (IV || ciphertext || ICV), for the caller to decrypt and re-parse.
func DecodeMessage(b []byte) (*Message, error) {
	h, err := decodeHeader(b)
	if err != nil {
		return nil, err
	}
	if int(h.Length) > len(b) {
		return nil, fmt.Errorf("ike: header length %d exceeds packet size %d", h.Length, len(b))
	}
	m := &Message{Header: *h}
	rest := b[HeaderLen:h.Length]
	next := h.NextPayload
	for next != PayloadNone {
		if len(rest) < genericPayloadHeaderLen {
			return nil, fmt.Errorf("ike: truncated payload header")
		}
		plLen := binary.BigEndian.Uint16(rest[2:4])
		if int(plLen) < genericPayloadHeaderLen || int(plLen) > len(rest) {
			return nil, fmt.Errorf("ike: invalid payload length %d", plLen)
		}
		p := RawPayload{
			Type:     next,
			Critical: rest[1]&0x80 != 0,
			Body:     rest[genericPayloadHeaderLen:plLen],
		}
		if p.Type == PayloadSK {
			m.skHeaderOffset = len(b) - len(rest)
		}
		next = PayloadType(rest[0])
		m.Payloads = append(m.Payloads, p)
		rest = rest[plLen:]
		// The SK payload's declared length only covers its own header +
		// ciphertext; everything else in the message is encrypted inside it,
		// so there is no further chain to walk in the outer message.
		if p.Type == PayloadSK {
			break
		}
	}
	return m, nil
}

func (m *Message) find(t PayloadType) *RawPayload {
	for i := range m.Payloads {
		if m.Payloads[i].Type == t {
			return &m.Payloads[i]
		}
	}
	return nil
}
