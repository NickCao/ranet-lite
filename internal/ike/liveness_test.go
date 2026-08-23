package ike

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

func TestSessionRunStopsOnContextCancellation(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	s := &Session{mux: mux}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Session.Run did not stop after context cancellation")
	}
}

func TestNextDueRekeyPreservesChildPriority(t *testing.T) {
	child := &rekeySchedule{name: "Child SA", due: true}
	ike := &rekeySchedule{name: "IKE SA", due: true}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, nil); got != child {
		t.Fatalf("first due schedule = %v, want Child SA", got)
	}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, child); got != nil {
		t.Fatalf("selected %v while another rekey was running", got)
	}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, nil); got != ike {
		t.Fatalf("second due schedule = %v, want IKE SA", got)
	}
}

func TestSupportedPayloadTypeRejectsUnknownCriticalType(t *testing.T) {
	if supportedPayloadType(PayloadType(250)) {
		t.Fatal("unknown payload type reported as supported")
	}
	if !supportedPayloadType(PayloadSA) {
		t.Fatal("SA payload type reported as unsupported")
	}
}

func TestRekeyRetryDelay(t *testing.T) {
	s := &Session{rekeyRetryInitial: 5 * time.Second, rekeyRetryMax: time.Minute}
	for _, test := range []struct {
		failures uint
		want     time.Duration
	}{
		{1, 5 * time.Second},
		{2, 10 * time.Second},
		{3, 20 * time.Second},
		{4, 40 * time.Second},
		{5, time.Minute},
		{6, time.Minute},
	} {
		if got := s.rekeyRetryDelay(test.failures); got != test.want {
			t.Errorf("retry delay after %d failures = %s, want %s", test.failures, got, test.want)
		}
	}
}

func TestRequestRetransmitDelayIsExponential(t *testing.T) {
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second}
	for i, delay := range want {
		if got := retransmitDelay(i + 1); got != delay {
			t.Fatalf("attempt %d delay = %v, want %v", i+1, got, delay)
		}
	}
}

func TestOnlyDPDExhaustsPostHandshakeRetransmits(t *testing.T) {
	ordinary := &pendingRequest{attempts: maxRetransmits}
	if pendingRetransmitsExhausted(ordinary) {
		t.Fatal("ordinary request exhausted retransmissions")
	}
	dpd := &pendingRequest{attempts: maxRetransmits, localRequest: localRequest{dpd: true}}
	if !pendingRetransmitsExhausted(dpd) {
		t.Fatal("DPD request did not exhaust retransmissions")
	}
}

func TestStartRequestConsumesMessageIDOnlyAfterSuccessfulSend(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	ctx := &ikeContext{
		suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128},
		skei:  make([]byte, 20), spiI: 1, spiR: 2, nextLocalMID: 7,
	}
	s := &Session{mux: mux, current: ctx}
	if _, err := s.startRequest(&localRequest{exchange: INFORMATIONAL}); err != nil {
		t.Fatal(err)
	}
	if ctx.nextLocalMID != 8 {
		t.Fatalf("Message ID after successful send = %d, want 8", ctx.nextLocalMID)
	}

	failedMux, err := transport.Dial(":0", net.IPv4(127, 0, 0, 1), 4500)
	if err != nil {
		t.Fatal(err)
	}
	if err := failedMux.Close(); err != nil {
		t.Fatal(err)
	}
	failedCtx := &ikeContext{
		suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128},
		skei:  make([]byte, 20), spiI: 3, spiR: 4, nextLocalMID: 11,
	}
	failed := &Session{mux: failedMux, current: failedCtx}
	if _, err := failed.startRequest(&localRequest{exchange: INFORMATIONAL}); err == nil {
		t.Fatal("startRequest succeeded with a closed transport")
	}
	if failedCtx.nextLocalMID != 11 {
		t.Fatalf("Message ID after failed send = %d, want 11", failedCtx.nextLocalMID)
	}
}

func TestReplayedRequestDoesNotRefreshOrAdoptEndpoint(t *testing.T) {
	configured := listenPeer(t)
	rebound := listenPeer(t)
	configuredAddr := configured.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", configuredAddr.IP, configuredAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  spiI,
		spiR:  spiR,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
	}
	s := &Session{mux: mux, current: ikeCtx}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: mux.LocalAddr().(*net.UDPAddr).Port}
	readIKE := func(peer *net.UDPConn) []byte {
		t.Helper()
		buf := make([]byte, 2048)
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), buf[4:n]...)
	}
	dispatchFrom := func(peer *net.UDPConn, request []byte) bool {
		t.Helper()
		if _, err := peer.WriteToUDP(withNonESPMarker(request), dst); err != nil {
			t.Fatal(err)
		}
		raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		var pending *pendingRequest
		return s.dispatch(raw, source, &pending)
	}

	request, err := EncryptMessage(suite, ikeCtx.sker, Header{
		SPIInitiator: spiI,
		SPIResponder: spiR,
		ExchangeType: INFORMATIONAL,
		MessageID:    0,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !dispatchFrom(configured, request) {
		t.Fatal("fresh request was not reported as peer activity")
	}
	response := readIKE(configured)

	if dispatchFrom(rebound, request) {
		t.Fatal("replayed request was reported as fresh peer activity")
	}
	if replayResponse := readIKE(rebound); !bytes.Equal(replayResponse, response) {
		t.Fatal("replayed request did not receive the cached response")
	}
	if err := mux.SendIKE([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	if got := readIKE(configured); string(got) != "probe" {
		t.Fatalf("packet after replay = %q, want configured endpoint", got)
	}

	freshRequest, err := EncryptMessage(suite, ikeCtx.sker, Header{
		SPIInitiator: spiI,
		SPIResponder: spiR,
		ExchangeType: INFORMATIONAL,
		MessageID:    1,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !dispatchFrom(rebound, freshRequest) {
		t.Fatal("fresh request from rebound endpoint was not reported as peer activity")
	}
	_ = readIKE(rebound)
	if err := mux.SendIKE([]byte("future")); err != nil {
		t.Fatal(err)
	}
	if got := readIKE(rebound); string(got) != "future" {
		t.Fatalf("packet after fresh request = %q, want rebound endpoint", got)
	}
}

func TestAuthenticatedMalformedRequestGetsInvalidSyntax(t *testing.T) {
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
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  spiI,
		spiR:  spiR,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
	}
	s := &Session{mux: mux, current: ikeCtx}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	// The authenticated plaintext contains a generic payload whose declared
	// length is shorter than its four-byte header, followed by zero padding.
	request, err := encryptMessagePlaintextIV(suite, ikeCtx.sker, Header{
		SPIInitiator: spiI,
		SPIResponder: spiR,
		ExchangeType: INFORMATIONAL,
		MessageID:    0,
	}, nil, PayloadN, []byte{0, 0, 0, 3, 0}, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: mux.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), dst); err != nil {
		t.Fatal(err)
	}
	raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var pending *pendingRequest
	if !s.dispatch(raw, source, &pending) {
		t.Fatal("authenticated malformed request was not handled")
	}

	buf := make([]byte, 2048)
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw := buf[4:n]
	response, err := DecodeMessage(responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ikeCtx.skei, responseRaw, response)
	if err != nil {
		t.Fatal(err)
	}
	if len(inner) != 1 || inner[0].Type != PayloadN {
		t.Fatalf("response payloads = %#v, want INVALID_SYNTAX", inner)
	}
	notify, err := DecodeNotify(inner[0].Body)
	if err != nil || notify.Type != N_INVALID_SYNTAX {
		t.Fatalf("response notify = %#v, %v", notify, err)
	}
	if !mux.IsClosed() {
		t.Fatal("IKE SA remained open after fatal INVALID_SYNTAX")
	}
}

func TestChildRequestRejectionNotifications(t *testing.T) {
	const unknownSPI = 0x10203040
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  0x0102030405060708,
		spiR:  0x1112131415161718,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
	}
	s := &Session{current: ikeCtx, Child: ChildSA{RemoteSPI: 0x50607080}}
	newSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(newSPI, 0x90a0b0c0)
	base := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: newSPI,
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}

	decodeResponse := func(raw []byte) Notify {
		t.Helper()
		message, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := DecryptMessage(suite, ikeCtx.skei, raw, message)
		if err != nil {
			t.Fatal(err)
		}
		if len(inner) != 1 || inner[0].Type != PayloadN {
			t.Fatalf("response payloads = %#v, want one Notify", inner)
		}
		notify, err := DecodeNotify(inner[0].Body)
		if err != nil {
			t.Fatal(err)
		}
		return notify
	}

	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	additionalRequest := append([]RawPayload(nil), base[:2]...)
	additionalRequest = append(additionalRequest, RawPayload{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())})
	additionalRequest = append(additionalRequest, base[2:]...)
	response, err := s.handleChildRekey(ikeCtx, 1, additionalRequest)
	if err != nil {
		t.Fatal(err)
	}
	additional := decodeResponse(response)
	if additional.Type != N_NO_ADDITIONAL_SAS || additional.Protocol != 0 || len(additional.SPI) != 0 {
		t.Fatalf("additional Child SA rejection = %#v", additional)
	}

	unknown := make([]byte, 4)
	binary.BigEndian.PutUint32(unknown, unknownSPI)
	rekey := append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Protocol: ProtoESP, SPI: unknown, Type: N_REKEY_SA})}}, base...)
	response, err = s.handleChildRekey(ikeCtx, 2, rekey)
	if err != nil {
		t.Fatal(err)
	}
	notFound := decodeResponse(response)
	if notFound.Type != N_CHILD_SA_NOT_FOUND || notFound.Protocol != ProtoESP || !bytes.Equal(notFound.SPI, unknown) {
		t.Fatalf("unknown Child SA rejection = %#v", notFound)
	}
}

func TestInformationalDeletesEveryDesignatedChildSA(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	current := ChildSA{LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	retiring := ChildSA{LocalSPI: 0x90a0b0c0, RemoteSPI: 0xd0e0f000}
	if err := mux.RegisterESP(current.LocalSPI); err != nil {
		t.Fatal(err)
	}
	if err := mux.RegisterESP(retiring.LocalSPI); err != nil {
		t.Fatal(err)
	}
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  0x0102030405060708,
		spiR:  0x1112131415161718,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
	}
	s := &Session{mux: mux, current: ikeCtx, Child: current, retiring: retiring}
	var retired []uint32
	s.SetChildRetireHandler(func(localSPI uint32) error {
		retired = append(retired, localSPI)
		return nil
	})
	spi := func(value uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, value)
		return b
	}
	response, err := s.handleRequest(ikeCtx, &Header{ExchangeType: INFORMATIONAL, MessageID: 4}, []RawPayload{
		{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi(current.RemoteSPI), spi(0xdeadbeef)}})},
		{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi(retiring.RemoteSPI)}})},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeMessage(response)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ikeCtx.skei, response, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(inner) != 1 || inner[0].Type != PayloadD {
		t.Fatalf("Delete response payloads = %#v", inner)
	}
	deleted, err := DecodeDelete(inner[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Protocol != ProtoESP || len(deleted.SPIs) != 2 || binary.BigEndian.Uint32(deleted.SPIs[0]) != current.LocalSPI || binary.BigEndian.Uint32(deleted.SPIs[1]) != retiring.LocalSPI {
		t.Fatalf("Delete response = %#v", deleted)
	}
	if len(retired) != 2 || retired[0] != current.LocalSPI || retired[1] != retiring.LocalSPI {
		t.Fatalf("retired SPIs = %08x", retired)
	}
	if got := s.currentChild(); got.LocalSPI != 0 || got.RemoteSPI != 0 {
		t.Fatalf("current Child SA remains: %#v", got)
	}
	if got := s.retiringChild(); got.LocalSPI != 0 || got.RemoteSPI != 0 {
		t.Fatalf("retiring Child SA remains: %#v", got)
	}
	if err := other.RegisterESP(current.LocalSPI); err != nil {
		t.Fatalf("current inbound SPI remains registered: %v", err)
	}
	if err := other.RegisterESP(retiring.LocalSPI); err != nil {
		t.Fatalf("retiring inbound SPI remains registered: %v", err)
	}
}

func TestInitialResponseHeaderValidation(t *testing.T) {
	req := &Header{SPIInitiator: 1, SPIResponder: 0, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0}
	valid := &Header{SPIInitiator: 1, SPIResponder: 2, MajorVersion: 2, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0, Length: HeaderLen}
	if !validResponseHeader(req, valid, HeaderLen) {
		t.Fatal("valid initial response rejected")
	}
	initialError := *valid
	initialError.SPIResponder = 0
	if !validResponseHeader(req, &initialError, HeaderLen) {
		t.Fatal("valid initial error response rejected")
	}
	mutations := []func(*Header){
		func(h *Header) { h.MajorVersion = 3 }, func(h *Header) { h.ExchangeType = IKE_AUTH },
		func(h *Header) { h.Flags |= FlagInitiator },
		func(h *Header) { h.SPIInitiator++ }, func(h *Header) { h.MessageID++ },
		func(h *Header) { h.Length++ },
	}
	for i, mutate := range mutations {
		got := *valid
		mutate(&got)
		if validResponseHeader(req, &got, HeaderLen) {
			t.Errorf("invalid header mutation %d accepted: %+v", i, got)
		}
	}
}

func TestSetRekeyRetry(t *testing.T) {
	s := new(Session)
	if err := s.SetRekeyRetry(5*time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
	if s.rekeyRetryInitial != 5*time.Second || s.rekeyRetryMax != time.Minute {
		t.Fatalf("retry delays = %s, %s", s.rekeyRetryInitial, s.rekeyRetryMax)
	}
	for _, delays := range [][2]time.Duration{{0, time.Second}, {time.Second, 0}, {time.Minute, time.Second}} {
		if err := s.SetRekeyRetry(delays[0], delays[1]); err == nil {
			t.Fatalf("SetRekeyRetry(%s, %s) succeeded", delays[0], delays[1])
		}
	}
}
