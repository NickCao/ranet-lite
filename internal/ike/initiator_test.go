package ike

import (
	"encoding/binary"
	"net"
	"sort"
	"sync"
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

func TestSessionRekeyChild(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	const oldLocalSPI = 0x10203040
	const oldRemoteSPI = 0x50607080
	const newRemoteSPI = 0x90a0b0c0
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	s := &Session{
		mux: mux, suite: suite, spiI: spiI, spiR: spiR, nextLocalMID: 2,
		skei: make([]byte, 20), sker: make([]byte, 20), skD: []byte("test child rekey SK_d material"),
		Child:    ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: oldLocalSPI, RemoteSPI: oldRemoteSPI},
		requests: make(chan *localRequest, 1),
	}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	installed := make(chan ChildSA, 1)
	s.SetChildHandler(func(child ChildSA) error {
		installed <- child
		return nil
	})

	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		buf := make([]byte, 2048)
		n, addr, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		raw := append([]byte(nil), buf[4:n]...)
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		inner, err := DecryptMessage(suite, s.skei, raw, m)
		if err != nil {
			t.Errorf("decrypt request: %v", err)
			return
		}
		if m.Header.ExchangeType != CREATE_CHILD_SA || findType(inner, PayloadKE) != nil {
			t.Errorf("unexpected rekey exchange")
			return
		}
		notifyPayload, saPayload := findType(inner, PayloadN), findType(inner, PayloadSA)
		noncePayload, tsiPayload, tsrPayload := findType(inner, PayloadNonce), findType(inner, PayloadTSi), findType(inner, PayloadTSr)
		if notifyPayload == nil || saPayload == nil || noncePayload == nil || tsiPayload == nil || tsrPayload == nil {
			t.Errorf("incomplete rekey request")
			return
		}
		notify, err := DecodeNotify(notifyPayload.Body)
		if err != nil || notify.Type != N_REKEY_SA || notify.Protocol != ProtoESP || len(notify.SPI) != 4 || binary.BigEndian.Uint32(notify.SPI) != oldRemoteSPI {
			t.Errorf("bad REKEY_SA notify: %#v, %v", notify, err)
			return
		}
		proposal, err := DecodeSA(saPayload.Body)
		if err != nil || len(proposal) != 1 || len(proposal[0].SPI) != 4 || binary.BigEndian.Uint32(proposal[0].SPI) == 0 {
			t.Errorf("bad proposal: %#v, %v", proposal, err)
			return
		}
		nonce := noncePayload.Body
		tsv4, tsv6 := FullRangeV4(), FullRangeV6()
		selectors := EncodeTS([]TrafficSelector{tsv4, tsv6})
		if len(nonce) == 0 || string(tsiPayload.Body) != string(selectors) || string(tsrPayload.Body) != string(selectors) {
			t.Errorf("bad rekey nonce or traffic selectors")
			return
		}
		remoteSPI := make([]byte, 4)
		binary.BigEndian.PutUint32(remoteSPI, newRemoteSPI)
		nr := []byte("responder nonce for child rekey")
		response, err := EncryptMessage(suite, s.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: CREATE_CHILD_SA, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: remoteSPI, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}}})},
			{Type: PayloadNonce, Body: EncodeNonce(nr)},
			{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
			{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
		})
		if err != nil {
			t.Errorf("encrypt response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write response: %v", err)
		}
	}()

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run() }()
	if err := s.RekeyChild(); err != nil {
		t.Fatalf("RekeyChild: %v", err)
	}
	<-peerDone
	child := <-installed
	if child.LocalSPI == oldLocalSPI || child.RemoteSPI != newRemoteSPI || len(child.InboundKey) == 0 || len(child.OutboundKey) == 0 {
		t.Fatalf("installed child = %#v", child)
	}
	if got := s.currentChild(); got.LocalSPI != child.LocalSPI || got.RemoteSPI != child.RemoteSPI || string(got.InboundKey) != string(child.InboundKey) || string(got.OutboundKey) != string(child.OutboundKey) {
		t.Fatalf("current child = %#v, want %#v", got, child)
	}
	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
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

func TestSessionRequestSerializesLocalMessageIDs(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	s := &Session{
		mux: mux, suite: suite, spiI: spiI, spiR: spiR, nextLocalMID: 2,
		skei: make([]byte, 20), sker: make([]byte, 20),
		requests: make(chan *localRequest, 1),
	}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	var ids []uint32
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		buf := make([]byte, 2048)
		for range 2 {
			n, addr, err := peer.ReadFromUDP(buf)
			if err != nil {
				t.Errorf("read request: %v", err)
				return
			}
			raw := append([]byte(nil), buf[4:n]...)
			m, err := DecodeMessage(raw)
			if err != nil {
				t.Errorf("decode request: %v", err)
				return
			}
			if _, err := DecryptMessage(suite, s.skei, raw, m); err != nil {
				t.Errorf("decrypt request: %v", err)
				return
			}
			ids = append(ids, m.Header.MessageID)
			response, err := EncryptMessage(suite, s.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: m.Header.ExchangeType, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, nil)
			if err != nil {
				t.Errorf("encrypt response: %v", err)
				return
			}
			if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
				t.Errorf("write response: %v", err)
				return
			}
		}
	}()

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run() }()
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.request(INFORMATIONAL, nil); err != nil {
				t.Errorf("request: %v", err)
			}
		}()
	}
	wg.Wait()
	<-peerDone
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) != 2 || ids[0] != 2 || ids[1] != 3 {
		t.Fatalf("local message IDs = %v, want [2 3]", ids)
	}
	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}
