package ike

import (
	"net"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

// listenPeer opens a plain UDP socket standing in for the IKE responder, so
// sendRecv's behavior can be tested without a real handshake.
func listenPeer(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func encodeTestMessage(t *testing.T, hdr Header, payloads []RawPayload) []byte {
	t.Helper()
	m := &Message{Header: hdr, Payloads: payloads}
	return m.Encode()
}

// withNonESPMarker prepends the 4-byte zero marker transport.Mux uses to
// demux IKE from ESP traffic (RFC 3948) -- without it, a reply sent by the
// mock peer below would be classified as ESP and never reach RecvIKEUntil.
func withNonESPMarker(b []byte) []byte {
	return append([]byte{0, 0, 0, 0}, b...)
}

// TestSendRecvIgnoresUnauthenticatedErrorNotify verifies the RFC 7815 §2.1
// fix directly: a bare, unauthenticated error notify (no SA payload, as an
// on-path attacker could forge given only the initiator's SPI, sent in the
// clear in the request) must not abort the exchange -- sendRecv must keep
// waiting and accept the real response that follows.
func TestSendRecvIgnoresUnauthenticatedErrorNotify(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI = 0x0102030405060708
	req := encodeTestMessage(t, Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0}, nil)

	accept := func(raw []byte) bool {
		m, err := DecodeMessage(raw)
		return err == nil && m.find(PayloadSA) != nil
	}

	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		raw, err := sendRecv(mux, req, accept)
		done <- result{raw, err}
	}()

	buf := make([]byte, 2048)
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, clientAddr, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer did not receive request: %v", err)
	}
	_ = n

	// Forged/unauthenticated error response: correlates by SPI+MessageID
	// but carries only a Notify, no SA -- accept() must reject this.
	bogus := withNonESPMarker(encodeTestMessage(t, Header{SPIInitiator: spiI, SPIResponder: 0xdead, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0},
		[]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})}}))
	if _, err := peer.WriteToUDP(bogus, clientAddr); err != nil {
		t.Fatal(err)
	}

	// The real response, sent right after: accept() must take this one.
	real := withNonESPMarker(encodeTestMessage(t, Header{SPIInitiator: spiI, SPIResponder: 0xf00d, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0},
		[]RawPayload{{Type: PayloadSA, Body: []byte{0x01, 0x02}}}))
	if _, err := peer.WriteToUDP(real, clientAddr); err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("sendRecv returned an error instead of the real response: %v", r.err)
		}
		got, err := DecodeMessage(r.raw)
		if err != nil {
			t.Fatalf("decode returned response: %v", err)
		}
		if got.find(PayloadSA) == nil {
			t.Fatal("sendRecv returned the bogus notify-only response instead of the real one")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sendRecv did not return in time -- likely blocked waiting past the accepted response")
	}
}

// TestSendRecvAcceptsNilAsAlwaysTrue verifies the nil-accept shorthand still
// treats the first correlated response as final, matching sendRecv's
// documented default.
func TestSendRecvAcceptsNilAsAlwaysTrue(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI = 0xaabbccddeeff0011
	req := encodeTestMessage(t, Header{SPIInitiator: spiI, ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: 3}, nil)

	done := make(chan []byte, 1)
	go func() {
		raw, err := sendRecv(mux, req, nil)
		if err != nil {
			t.Errorf("sendRecv: %v", err)
			return
		}
		done <- raw
	}()

	buf := make([]byte, 2048)
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, clientAddr, err := peer.ReadFromUDP(buf); err != nil {
		t.Fatalf("peer did not receive request: %v", err)
	} else {
		resp := withNonESPMarker(encodeTestMessage(t, Header{SPIInitiator: spiI, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: 3}, nil))
		if _, err := peer.WriteToUDP(resp, clientAddr); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sendRecv with nil accept did not return")
	}
}
