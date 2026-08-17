package babel

import (
	"net/netip"
	"testing"
)

func TestRawPacketRoundTrip(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	payload := EncodePacket([]RawTLV{EncodeAck(42)})

	pkt := buildPacket(src, multicastGroup, payload)
	gotSrc, gotPayload, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if gotSrc != src {
		t.Fatalf("src = %v, want %v", gotSrc, src)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("payload mismatch: got %x want %x", gotPayload, payload)
	}
}

func TestRawPacketRejectsWrongPort(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	pkt := buildPacket(src, multicastGroup, []byte{1, 2, 3})
	// Corrupt the destination port.
	pkt[ipv6HeaderLen+2] ^= 0xff
	if _, _, err := parsePacket(pkt); err == nil {
		t.Fatal("expected rejection of a packet not addressed to the babel port")
	}
}

func TestRawPacketRejectsTamperedLength(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	pkt := buildPacket(src, multicastGroup, []byte{1, 2, 3})
	pkt = pkt[:len(pkt)-1] // truncate
	if _, _, err := parsePacket(pkt); err == nil {
		t.Fatal("expected rejection of a truncated packet")
	}
}
