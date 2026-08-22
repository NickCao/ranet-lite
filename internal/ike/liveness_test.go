package ike

import (
	"context"
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
