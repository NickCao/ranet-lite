package ike

import (
	"bytes"
	"testing"
)

func TestDeleteRoundTrip(t *testing.T) {
	want := Delete{Protocol: ProtoESP, SPIs: [][]byte{{0, 0, 0, 1}, {0, 0, 0, 2}}}
	got, err := DecodeDelete(EncodeDelete(want))
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != want.Protocol || len(got.SPIs) != len(want.SPIs) {
		t.Fatalf("decoded delete = %#v, want %#v", got, want)
	}
	for i := range want.SPIs {
		if !bytes.Equal(got.SPIs[i], want.SPIs[i]) {
			t.Fatalf("SPI %d = %x, want %x", i, got.SPIs[i], want.SPIs[i])
		}
	}
}

func TestDecodeDeleteRejectsTruncatedSPI(t *testing.T) {
	if _, err := DecodeDelete([]byte{byte(ProtoESP), 4, 0, 1, 0, 0, 0}); err == nil {
		t.Fatal("DecodeDelete accepted a truncated SPI")
	}
}
