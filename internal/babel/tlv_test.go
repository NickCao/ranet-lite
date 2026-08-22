package babel

import (
	"net"
	"net/netip"
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

func TestUpdateRouterIDFlagDerivesAndUpdatesState(t *testing.T) {
	body := EncodeUpdate(Update{AE: AEIPv6, Plen: 128, Prefix: net.ParseIP("2001:db8::0102:0304:0506:0708")}).Body
	body[1] |= updateFlagRouterID | 0x01 // unknown flag bits are ignored
	got, err := (&PrefixDecoder{}).Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	want := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if got.Ignore || !got.HasRouterID || got.RouterID != want {
		t.Fatalf("R-flag Update = %+v, want router-id %x", got, want)
	}
	v4 := EncodeUpdate(Update{AE: AEIPv4, Plen: 25, Prefix: net.IPv4(192, 0, 2, 255)}).Body
	v4[1] |= updateFlagRouterID
	got, err = (&PrefixDecoder{}).Decode(v4)
	if err != nil {
		t.Fatal(err)
	}
	want = [8]byte{0, 0, 0, 0, 192, 0, 2, 128}
	if got.RouterID != want {
		t.Fatalf("masked IPv4 R-flag router-id = %x, want %x", got.RouterID, want)
	}
}

func TestRequestRoundTrips(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8::/64")
	route, err := DecodeRouteRequest(EncodeRouteRequest(RouteRequest{AE: AEIPv6, Prefix: prefix}).Body)
	if err != nil || route.Prefix != prefix {
		t.Fatalf("Route Request = %+v, %v", route, err)
	}
	want := SeqnoRequest{AE: AEIPv6, Prefix: prefix, Seqno: 42, HopCount: 64, RouterID: [8]byte{1, 2, 3}}
	seqno, err := DecodeSeqnoRequest(EncodeSeqnoRequest(want).Body)
	if err != nil || seqno != want {
		t.Fatalf("Seqno Request = %+v, %v; want %+v", seqno, err, want)
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

func TestUpdateCompressionRequiresPrefixFlag(t *testing.T) {
	decoder := &PrefixDecoder{}
	first := EncodeUpdate(Update{AE: AEIPv4, Plen: 32, Prefix: net.IPv4(10, 0, 0, 1)})
	if _, err := decoder.Decode(first.Body); err != nil {
		t.Fatal(err)
	}
	compressed := []byte{AEIPv4, 0, 32, 3, 0, 0, 0, 0, 0, 1, 2}
	if _, err := decoder.Decode(compressed); err != nil {
		t.Fatal(err)
	}
	if _, err := (&PrefixDecoder{}).Decode(compressed); err == nil {
		t.Fatal("accepted compressed Update without a P-flag default")
	}
}

func TestUpdateRejectsPrefixLengthBeyondAddressFamily(t *testing.T) {
	for _, body := range [][]byte{
		{AEIPv4, 0, 40, 5, 0, 0, 0, 0, 0, 0},
		{AEIPv6, 0, 136, 17, 0, 0, 0, 0, 0, 0},
	} {
		if _, err := (&PrefixDecoder{}).Decode(body); err == nil {
			t.Fatalf("Decode accepted invalid Update body %x", body)
		}
	}
}

func TestWildcardUpdateRequiresInfiniteMetric(t *testing.T) {
	finite := []byte{AEWildcard, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	got, err := (&PrefixDecoder{}).Decode(finite)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Ignore {
		t.Fatal("accepted finite wildcard Update")
	}
}

// TestUpdateWithSourcePrefix guards real-world SADR interop (e.g. BIRD's
// "ipv6 sadr" tables, draft-ietf-babel-source-specific): a well-formed
// Source Prefix sub-TLV (type 128, mandatory bit set per RFC 8966 §4.4)
// must be parsed into Update.SourcePrefix, not treated as an ordinary
// destination-only route or blanket-ignored — Speaker decides relevance
// by checking whether SourcePrefix covers its own source address (see
// TestSpeakerSADR). It must still update prefix-compression state
// regardless, since RFC 8966 requires the parser state to advance even
// for an otherwise-ignored TLV.
func TestUpdateWithSourcePrefix(t *testing.T) {
	dec := &PrefixDecoder{}

	// AE=IPv4, Plen=32, prefix 10.99.2.5, trailing Source Prefix sub-TLV
	// (type 128, SourcePlen=16, source prefix 10.1.0.0/16).
	body := []byte{
		AEIPv4, updateFlagPrefix, 32, 0, // AE, Flags, Plen, Omitted
		0, 0, // Interval
		0, 0, // Seqno
		0, 128, // Metric
		10, 99, 2, 5, // Prefix
		128, 3, 16, 10, 1, // Source Prefix sub-TLV
	}
	got, err := dec.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ignore {
		t.Fatal("a well-formed Source Prefix sub-TLV should not set Ignore")
	}
	wantSource := netip.MustParsePrefix("10.1.0.0/16")
	if got.SourcePrefix != wantSource {
		t.Fatalf("SourcePrefix = %v, want %v", got.SourcePrefix, wantSource)
	}
	if !got.Prefix.Equal(net.IPv4(10, 99, 2, 5)) {
		t.Fatalf("prefix = %v, want 10.99.2.5", got.Prefix)
	}

	// Compression state must still have advanced, per RFC 8966 §4.4/§4.5
	// — a following compressed Update referencing its prefix bytes must
	// decode correctly.
	compressed := []byte{AEIPv4, 0, 32, 3, 0, 0, 0, 0, 0, 0, 9}
	got2, err := dec.Decode(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if !got2.Prefix.Equal(net.IPv4(10, 99, 2, 9)) {
		t.Fatalf("compressed prefix after an ignored Update = %v, want 10.99.2.9", got2.Prefix)
	}
}

func TestUpdateIgnoresTruncatedMandatorySubTLV(t *testing.T) {
	body := []byte{
		AEIPv4, 0, 32, 0, 0, 0, 0, 1, 0, 64,
		10, 0, 0, 1,
		SubTLVSourcePrefix, 3, 16, 10,
	}
	got, err := (&PrefixDecoder{}).Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Ignore {
		t.Fatal("Update accepted a truncated mandatory sub-TLV")
	}
}

func TestHelloRejectsTruncatedSubTLV(t *testing.T) {
	body := append(make([]byte, 6), SubTLVTimestamp, 4, 0)
	if _, err := DecodeHello(body); err == nil {
		t.Fatal("DecodeHello accepted a truncated sub-TLV")
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

func TestDecodePacketRejectsUnsupportedVersion(t *testing.T) {
	packet := EncodePacket(nil)
	packet[1] = Version + 1
	if _, err := DecodePacket(packet); err == nil {
		t.Fatal("DecodePacket accepted an unsupported version")
	}
}
