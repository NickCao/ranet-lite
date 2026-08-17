package ike

import (
	"encoding/binary"
	"fmt"
)

// HeaderLen is the fixed size of the IKE header, RFC 7296 §3.1.
const HeaderLen = 28

// Header is the fixed IKEv2 message header.
type Header struct {
	SPIInitiator  uint64
	SPIResponder  uint64
	NextPayload   PayloadType
	MajorVersion  uint8
	MinorVersion  uint8
	ExchangeType  ExchangeType
	Flags         uint8
	MessageID     uint32
	Length        uint32 // total message length including header; filled on encode
}

func (h *Header) IsResponse() bool   { return h.Flags&FlagResponse != 0 }
func (h *Header) IsInitiator() bool  { return h.Flags&FlagInitiator != 0 }

func (h *Header) encode() []byte {
	b := make([]byte, HeaderLen)
	binary.BigEndian.PutUint64(b[0:8], h.SPIInitiator)
	binary.BigEndian.PutUint64(b[8:16], h.SPIResponder)
	b[16] = byte(h.NextPayload)
	b[17] = 0x20 // IKEv2: major version 2, minor version 0 (this package speaks nothing else)
	b[18] = byte(h.ExchangeType)
	b[19] = h.Flags
	binary.BigEndian.PutUint32(b[20:24], h.MessageID)
	binary.BigEndian.PutUint32(b[24:28], h.Length)
	return b
}

func decodeHeader(b []byte) (*Header, error) {
	if len(b) < HeaderLen {
		return nil, fmt.Errorf("ike: short header (%d bytes)", len(b))
	}
	h := &Header{
		SPIInitiator: binary.BigEndian.Uint64(b[0:8]),
		SPIResponder: binary.BigEndian.Uint64(b[8:16]),
		NextPayload:  PayloadType(b[16]),
		MajorVersion: b[17] >> 4,
		MinorVersion: b[17] & 0x0f,
		ExchangeType: ExchangeType(b[18]),
		Flags:        b[19],
		MessageID:    binary.BigEndian.Uint32(b[20:24]),
		Length:       binary.BigEndian.Uint32(b[24:28]),
	}
	return h, nil
}
