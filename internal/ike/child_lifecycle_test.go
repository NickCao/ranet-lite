package ike

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/NickCao/ranet-lite/internal/transport"
)

func lifecycleMuxes(t *testing.T) (*transport.Mux, *transport.Mux) {
	t.Helper()
	hub, err := transport.NewHub(":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.Close() })
	first, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4500)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4501)
	if err != nil {
		t.Fatal(err)
	}
	return first, second
}

func TestReplaceChildRollsBackSPIRegistration(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	s := &Session{mux: mux}
	s.SetChildHandler(func(ChildSA) error { return errors.New("install failed") })
	child := ChildSA{LocalSPI: 0x10203040}
	if err := s.replaceChild(child); err == nil {
		t.Fatal("replaceChild succeeded after handler failure")
	}
	if err := other.RegisterESP(child.LocalSPI); err != nil {
		t.Fatalf("failed installation retained SPI registration: %v", err)
	}
}

func TestRetireChildPreservesRetryableStateOnFailure(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	old := ChildSA{LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	s := &Session{mux: mux, retiring: old}
	s.SetChildRetireHandler(func(uint32) error { return errors.New("remove failed") })
	if err := s.retireChild(old.RemoteSPI); err == nil {
		t.Fatal("retireChild succeeded after handler failure")
	}
	if got := s.retiringChild(); got.LocalSPI != old.LocalSPI || got.RemoteSPI != old.RemoteSPI {
		t.Fatalf("retiring Child SA changed after failure: got %+v, want %+v", got, old)
	}
	if err := other.RegisterESP(old.LocalSPI); err == nil {
		t.Fatal("failed retirement released the inbound SPI")
	}

	s.SetChildRetireHandler(func(uint32) error { return nil })
	if err := s.retireChild(old.RemoteSPI); err != nil {
		t.Fatal(err)
	}
	if err := other.RegisterESP(old.LocalSPI); err != nil {
		t.Fatalf("successful retirement retained SPI registration: %v", err)
	}
}

func TestReplaceChildRejectsOverlappingRetirement(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	s := &Session{mux: mux, retiring: ChildSA{LocalSPI: 1, RemoteSPI: 2}}
	if err := s.replaceChild(ChildSA{LocalSPI: 3, RemoteSPI: 4}); err == nil {
		t.Fatal("replaceChild replaced an SA while an earlier one was still retiring")
	}
}

func TestProactiveChildRekeyCoalescesWithRunningExchange(t *testing.T) {
	s := new(Session)
	s.childRekeying.Store(true)
	if err := s.RekeyChildProactively(); err != nil {
		t.Fatalf("proactive rekey did not coalesce: %v", err)
	}
	if err := s.RekeyChild(); err == nil {
		t.Fatal("ordinary rekey did not report the running exchange")
	}
}

func TestChildRekeyGuardSerializesAttempts(t *testing.T) {
	s := &Session{}
	if !s.childRekeying.CompareAndSwap(false, true) {
		t.Fatal("failed to reserve Child rekey")
	}
	if s.childRekeying.CompareAndSwap(false, true) {
		t.Fatal("reserved a second simultaneous Child rekey")
	}
}

func TestChildNotFoundRecoveryCreatesNewChild(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	old := ChildSA{
		EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128,
		LocalSPI: 0x10203040, RemoteSPI: 0x50607080,
	}
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	s := &Session{
		mux: mux,
		current: &ikeContext{
			suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256},
			skD:   []byte("test child replacement SK_d material"),
		},
		Child:    old,
		requests: make(chan *localRequest),
	}
	var retired uint32
	s.SetChildRetireHandler(func(localSPI uint32) error {
		retired = localSPI
		return nil
	})
	var installed ChildSA
	s.SetChildHandler(func(child ChildSA) error {
		installed = child
		return nil
	})

	done := make(chan error, 1)
	go func() { done <- s.RekeyChild() }()
	first := <-s.requests
	rekeyPayload := findType(first.inner, PayloadN)
	if first.exchange != CREATE_CHILD_SA || rekeyPayload == nil {
		t.Fatalf("first request is not a Child SA rekey: %#v", first.inner)
	}
	rekey, err := DecodeNotify(rekeyPayload.Body)
	if err != nil || rekey.Type != N_REKEY_SA || binary.BigEndian.Uint32(rekey.SPI) != old.LocalSPI {
		t.Fatalf("first REKEY_SA = %#v, %v", rekey, err)
	}
	missingSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(missingSPI, old.LocalSPI)
	first.result <- requestResult{inner: []RawPayload{{
		Type: PayloadN,
		Body: EncodeNotify(Notify{Protocol: ProtoESP, SPI: missingSPI, Type: N_CHILD_SA_NOT_FOUND}),
	}}}

	second := <-s.requests
	if second.exchange != CREATE_CHILD_SA || findType(second.inner, PayloadN) != nil {
		t.Fatalf("replacement request still contains REKEY_SA: %#v", second.inner)
	}
	requestPayloads, err := decodeChildExchangePayloads(second.inner)
	if err != nil {
		t.Fatalf("invalid replacement request: %v", err)
	}
	proposals, err := DecodeSA(requestPayloads.sa.Body)
	if err != nil || len(proposals) != 1 || len(proposals[0].SPI) != 4 {
		t.Fatalf("invalid replacement proposal: %#v, %v", proposals, err)
	}
	newLocalSPI := binary.BigEndian.Uint32(proposals[0].SPI)
	newRemoteSPI := uint32(0x90a0b0c0)
	remoteSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(remoteSPI, newRemoteSPI)
	second.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: remoteSPI,
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if retired != old.LocalSPI {
		t.Fatalf("retired SPI = %08x, want %08x", retired, old.LocalSPI)
	}
	if installed.LocalSPI != newLocalSPI || installed.RemoteSPI != newRemoteSPI {
		t.Fatalf("installed Child SA = %#v", installed)
	}
	if got := s.currentChild(); got.LocalSPI != newLocalSPI || got.RemoteSPI != newRemoteSPI {
		t.Fatalf("current Child SA = %#v", got)
	}
}
