package ike

import (
	"encoding/binary"
	"testing"
)

func TestDecodeMessageRejectsInvalidDeclaredExtent(t *testing.T) {
	for _, length := range []uint32{0, HeaderLen - 1, HeaderLen + 1} {
		raw := make([]byte, HeaderLen)
		binary.BigEndian.PutUint32(raw[24:28], length)
		if _, err := DecodeMessage(raw); err == nil {
			t.Fatalf("DecodeMessage accepted declared length %d for %d-byte packet", length, len(raw))
		}
	}
}

func TestDecodeMessageRejectsTrailingPayloadBytes(t *testing.T) {
	raw := (&Header{Length: HeaderLen + 1}).encode()
	raw = append(raw, 0)
	if _, err := DecodeMessage(raw); err == nil {
		t.Fatal("DecodeMessage accepted bytes after an empty payload chain")
	}
}
