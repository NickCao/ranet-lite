package babel

import (
	"net/netip"
	"testing"
)

func TestRawPacketRoundTrip(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	payload := EncodePacket([]RawTLV{EncodeAck(42)})

	pkt := buildPacket(src, multicastGroup, payload)
	gotSrc, gotPayload, err := parsePacket(pkt, src)
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
	if _, _, err := parsePacket(pkt, src); err == nil {
		t.Fatal("expected rejection of a packet not addressed to the babel port")
	}
}

func TestRawPacketRejectsTamperedLength(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	pkt := buildPacket(src, multicastGroup, []byte{1, 2, 3})
	pkt = pkt[:len(pkt)-1] // truncate
	if _, _, err := parsePacket(pkt, src); err == nil {
		t.Fatal("expected rejection of a truncated packet")
	}
}

func TestRawPacketRejectsInvalidEnvelope(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	for name, mutate := range map[string]func([]byte){
		"source port":    func(packet []byte) { packet[40], packet[41] = 0, 1 },
		"source address": func(packet []byte) { copy(packet[8:24], netip.MustParseAddr("2001:db8::1").AsSlice()) },
		"destination":    func(packet []byte) { copy(packet[24:40], netip.MustParseAddr("ff02::1").AsSlice()) },
		"payload length": func(packet []byte) { packet[5]++ },
		"checksum":       func(packet []byte) { packet[46] ^= 0xff },
	} {
		t.Run(name, func(t *testing.T) {
			packet := buildPacket(src, multicastGroup, EncodePacket(nil))
			mutate(packet)
			if _, _, err := parsePacket(packet, src); err == nil {
				t.Fatal("parsePacket accepted invalid envelope")
			}
		})
	}
}

func TestRawPacketAcceptsLocalUnicastDestination(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	local := netip.MustParseAddr("fe80::2")
	packet := buildPacket(src, local, EncodePacket([]RawTLV{EncodeAck(1)}))
	if _, _, err := parsePacket(packet, local); err != nil {
		t.Fatal(err)
	}
}
