package babel

import (
	"net"
	"testing"
)

func TestHelloRoundTrip(t *testing.T) {
	h := Hello{Seqno: 42, Interval: 2000, TxTS: 123456, HasTS: true}
	tlv := EncodeHello(h)
	pkt := EncodePacket([]RawTLV{tlv})
	got, err := DecodePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Type != TLVHello {
		t.Fatalf("unexpected decoded TLVs: %+v", got)
	}
	h2, err := DecodeHello(got[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if h2 != h {
		t.Fatalf("got %+v, want %+v", h2, h)
	}
}

func TestIHURoundTrip(t *testing.T) {
	ihu := IHU{RxCost: 96, Interval: 2000, OriginTS: 111, ReceiveTS: 222, HasTS: true}
	tlv := EncodeIHU(ihu)
	decoded, addr, err := DecodeIHU(tlv.Body)
	if err != nil {
		t.Fatal(err)
	}
	if addr != nil {
		t.Fatalf("expected nil address for wildcard AE, got %v", addr)
	}
	if decoded != ihu {
		t.Fatalf("got %+v, want %+v", decoded, ihu)
	}
}

func TestUpdateRoundTripNoCompression(t *testing.T) {
	u := Update{AE: AEIPv4, Plen: 32, Interval: 3000, Seqno: 1, Metric: 128, Prefix: net.IPv4(10, 99, 1, 1)}
	tlv := EncodeUpdate(u)
	dec := &PrefixDecoder{}
	got, err := dec.Decode(tlv.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Plen != u.Plen || got.Metric != u.Metric || got.Seqno != u.Seqno || !got.Prefix.Equal(u.Prefix) {
		t.Fatalf("got %+v, want %+v", got, u)
	}
}

func TestUpdatePrefixCompression(t *testing.T) {
	// Simulate what a compressing sender (e.g. BIRD) would produce: two
	// IPv4 /32 updates sharing the first 3 bytes, second one omits them.
	dec := &PrefixDecoder{}

	first := EncodeUpdate(Update{AE: AEIPv4, Plen: 32, Metric: 128, Prefix: net.IPv4(10, 99, 1, 1)})
	got1, err := dec.Decode(first.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !got1.Prefix.Equal(net.IPv4(10, 99, 1, 1)) {
		t.Fatalf("first prefix = %v", got1.Prefix)
	}

	// Hand-build a compressed second Update: AE=IPv4, Plen=32, Omitted=3,
	// only the last byte (2) is sent.
	body := []byte{AEIPv4, 0, 32, 3, 0, 0, 0, 0, 0, 128, 2}
	got2, err := dec.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got2.Prefix.Equal(net.IPv4(10, 99, 1, 2)) {
		t.Fatalf("compressed prefix = %v, want 10.99.1.2", got2.Prefix)
	}
}

func TestRouterIDRoundTrip(t *testing.T) {
	id := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	tlv := EncodeRouterID(id)
	got, err := DecodeRouterID(tlv.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("got %v, want %v", got, id)
	}
}

func TestNextHopRoundTrip(t *testing.T) {
	addr := net.ParseIP("10.99.1.1").To4()
	tlv := EncodeNextHop(addr)
	got, err := DecodeNextHop(tlv.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(addr) {
		t.Fatalf("got %v, want %v", got, addr)
	}
}

func TestDecodePacketSkipsPadding(t *testing.T) {
	pkt := EncodePacket([]RawTLV{
		{Type: TLVPad1, Body: nil},
		{Type: TLVPadN, Body: []byte{0, 0, 0}},
		{Type: TLVAck, Body: []byte{0, 1}},
	})
	got, err := DecodePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Type != TLVAck {
		t.Fatalf("expected only the Ack TLV to survive, got %+v", got)
	}
}
