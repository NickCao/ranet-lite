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

func TestDecodeDeleteEnforcesProtocolSPISize(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"IKE SPI", []byte{byte(ProtoIKE), 4, 0, 1, 0, 0, 0, 1}},
		{"IKE count", []byte{byte(ProtoIKE), 0, 0, 1}},
		{"ESP size", []byte{byte(ProtoESP), 0, 0, 0}},
		{"AH size", []byte{byte(ProtoAH), 8, 0, 0}},
		{"protocol", []byte{99, 4, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeDelete(test.body); err == nil {
				t.Fatal("DecodeDelete accepted invalid Delete payload")
			}
		})
	}
}

func TestDecodeTSRejectsUndersizedSelector(t *testing.T) {
	body := []byte{1, 0, 0, 0, 7, 0, 0, 7, 0, 0, 0}
	if _, err := DecodeTS(body); err == nil {
		t.Fatal("DecodeTS accepted a selector shorter than its fixed header")
	}
}
