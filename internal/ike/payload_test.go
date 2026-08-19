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

func TestIKEContextAllocatesUniqueIVs(t *testing.T) {
	context := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}}
	key := make([]byte, 20)
	first, err := context.encrypt(key, Header{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := context.encrypt(key, Header{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstIV := first[HeaderLen+genericPayloadHeaderLen : HeaderLen+genericPayloadHeaderLen+8]
	secondIV := second[HeaderLen+genericPayloadHeaderLen : HeaderLen+genericPayloadHeaderLen+8]
	if string(firstIV) == string(secondIV) {
		t.Fatalf("reused IKE IV %x", firstIV)
	}
}
