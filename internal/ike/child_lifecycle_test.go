package ike

import (
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
