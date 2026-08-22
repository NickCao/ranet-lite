package ike

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
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

func TestSessionScheduledRekeyFailureRetries(t *testing.T) {
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
		mux: mux,
		current: &ikeContext{suite: suite, spiI: spiI, spiR: spiR, nextLocalMID: 2,
			skei: make([]byte, 20), sker: make([]byte, 20), skD: []byte("test child rekey SK_d material")},
		Child:    ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080},
		requests: make(chan *localRequest, 1),
	}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRekeyIntervals(time.Millisecond, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRekeyRetry(10*time.Millisecond, time.Second); err != nil {
		t.Fatal(err)
	}

	retried := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		n, addr, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read scheduled rekey request: %v", err)
			return
		}
		raw := append([]byte(nil), buf[4:n]...)
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode scheduled rekey request: %v", err)
			return
		}
		response, err := EncryptMessage(suite, s.current.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: m.Header.ExchangeType, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})}})
		if err != nil {
			t.Errorf("encrypt scheduled rekey response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write scheduled rekey response: %v", err)
			return
		}
		if _, _, err := peer.ReadFromUDP(buf); err != nil {
			t.Errorf("read scheduled rekey retry: %v", err)
			return
		}
		close(retried)
	}()

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()
	select {
	case <-retried:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled rekey was not retried")
	}
	select {
	case err := <-runDone:
		t.Fatalf("Run returned after scheduled rekey failure: %v", err)
	default:
	}
	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}

func TestRekeyDelay(t *testing.T) {
	s := &Session{rekeyMargin: 5 * time.Minute, rekeyJitter: time.Minute}
	var limits []time.Duration
	s.rekeyJitterSource = func(max time.Duration) (time.Duration, error) {
		limits = append(limits, max)
		return max, nil
	}

	delay, err := s.rekeyDelay(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if want := 54 * time.Minute; delay != want {
		t.Fatalf("rekey delay = %s, want %s", delay, want)
	}
	if len(limits) != 1 || limits[0] != time.Minute {
		t.Fatalf("jitter limits = %v, want [%s]", limits, time.Minute)
	}

	s.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return time.Minute + time.Nanosecond, nil }
	if _, err := s.rekeyDelay(time.Hour); err == nil {
		t.Fatal("rekeyDelay succeeded with out-of-range jitter")
	}
}

func TestSessionScheduledRekeyChild(t *testing.T) {
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
		mux: mux,
		current: &ikeContext{suite: suite, spiI: spiI, spiR: spiR, nextLocalMID: 2,
			skei: make([]byte, 20), sker: make([]byte, 20), skD: []byte("test child rekey SK_d material")},
		Child:    ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: oldLocalSPI, RemoteSPI: oldRemoteSPI},
		requests: make(chan *localRequest, 1),
	}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	s.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
	if err := s.SetRekeyTiming(0, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRekeyIntervals(25*time.Millisecond, 0); err != nil {
		t.Fatal(err)
	}
	installed := make(chan ChildSA, 1)
	s.SetChildHandler(func(child ChildSA) error {
		installed <- child
		return nil
	})
	rekeyed := make(chan struct{})
	s.SetChildRetireHandler(func(spi uint32) error {
		if spi != oldLocalSPI {
			t.Errorf("retired SPI = %08x, want %08x", spi, oldLocalSPI)
		}
		close(rekeyed)
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
		inner, err := DecryptMessage(suite, s.current.skei, raw, m)
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
		if err != nil || notify.Type != N_REKEY_SA || notify.Protocol != ProtoESP || len(notify.SPI) != 4 || binary.BigEndian.Uint32(notify.SPI) != oldLocalSPI {
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
		response, err := EncryptMessage(suite, s.current.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: CREATE_CHILD_SA, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, []RawPayload{
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
			return
		}
		n, addr, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read delete request: %v", err)
			return
		}
		raw = append([]byte(nil), buf[4:n]...)
		m, err = DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode delete request: %v", err)
			return
		}
		inner, err = DecryptMessage(suite, s.current.skei, raw, m)
		if err != nil {
			t.Errorf("decrypt delete request: %v", err)
			return
		}
		dp := findType(inner, PayloadD)
		if m.Header.ExchangeType != INFORMATIONAL || dp == nil {
			t.Errorf("unexpected retire exchange")
			return
		}
		d, err := DecodeDelete(dp.Body)
		if err != nil || d.Protocol != ProtoESP || len(d.SPIs) != 1 || len(d.SPIs[0]) != 4 || binary.BigEndian.Uint32(d.SPIs[0]) != oldLocalSPI {
			t.Errorf("bad retire delete: %#v, %v", d, err)
			return
		}
		remote := make([]byte, 4)
		binary.BigEndian.PutUint32(remote, oldRemoteSPI)
		response, err = EncryptMessage(suite, s.current.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{remote}})}})
		if err != nil {
			t.Errorf("encrypt delete response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write delete response: %v", err)
			return
		}
		n, addr, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read post-rekey request: %v", err)
			return
		}
		raw = append([]byte(nil), buf[4:n]...)
		m, err = DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode post-rekey request: %v", err)
			return
		}
		if _, err := DecryptMessage(suite, s.current.skei, raw, m); err != nil {
			t.Errorf("decrypt post-rekey request: %v", err)
			return
		}
		if m.Header.ExchangeType != INFORMATIONAL {
			t.Errorf("post-rekey exchange = %d, want INFORMATIONAL", m.Header.ExchangeType)
			return
		}
		response, err = EncryptMessage(suite, s.current.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, nil)
		if err != nil {
			t.Errorf("encrypt post-rekey response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write post-rekey response: %v", err)
		}
	}()

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()
	select {
	case <-rekeyed:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled Child SA rekey did not complete")
	}
	if _, err := s.request(INFORMATIONAL, nil); err != nil {
		t.Fatalf("post-rekey request: %v", err)
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

func TestSessionRekeyIKE(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const oldSPIi = 0x0102030405060708
	const oldSPIr = 0x1112131415161718
	const newSPIr = 0x2122232425262728
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: oldSPIi, spiR: oldSPIr, nextLocalMID: 2,
		skD: []byte("old IKE rekey SK_d material-------"), skei: make([]byte, 20), sker: make([]byte, 20)}
	child := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	s := &Session{mux: mux, current: old, Child: child, requests: make(chan *localRequest, 1)}
	if err := mux.RegisterIKE(oldSPIi); err != nil {
		t.Fatal(err)
	}

	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		buf := make([]byte, 2048)
		n, addr, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read rekey request: %v", err)
			return
		}
		raw := append([]byte(nil), buf[4:n]...)
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode rekey request: %v", err)
			return
		}
		inner, err := DecryptMessage(suite, old.skei, raw, m)
		if err != nil {
			t.Errorf("decrypt rekey request: %v", err)
			return
		}
		sa, nonce, ke := findType(inner, PayloadSA), findType(inner, PayloadNonce), findType(inner, PayloadKE)
		if m.Header.ExchangeType != CREATE_CHILD_SA || m.Header.MessageID != 2 || sa == nil || nonce == nil || ke == nil {
			t.Errorf("incomplete IKE rekey request")
			return
		}
		props, err := DecodeSA(sa.Body)
		if err != nil || len(props) != 1 || props[0].Protocol != ProtoIKE || len(props[0].SPI) != 8 {
			t.Errorf("bad IKE rekey proposal: %#v, %v", props, err)
			return
		}
		newSPIi := binary.BigEndian.Uint64(props[0].SPI)
		group, _, err := DecodeKE(ke.Body)
		if err != nil || group != DH_CURVE25519 || len(nonce.Body) == 0 || newSPIi == 0 {
			t.Errorf("bad IKE rekey KE or nonce: %d, %v", group, err)
			return
		}
		invalidKEData := make([]byte, 2)
		binary.BigEndian.PutUint16(invalidKEData, DH_ECP_256)
		response, err := EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, []RawPayload{
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INVALID_KE_PAYLOAD, Data: invalidKEData})},
		})
		if err != nil {
			t.Errorf("encrypt INVALID_KE_PAYLOAD response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write INVALID_KE_PAYLOAD response: %v", err)
			return
		}

		n, addr, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read retried rekey request: %v", err)
			return
		}
		raw = append([]byte(nil), buf[4:n]...)
		m, err = DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode retried rekey request: %v", err)
			return
		}
		inner, err = DecryptMessage(suite, old.skei, raw, m)
		if err != nil {
			t.Errorf("decrypt retried rekey request: %v", err)
			return
		}
		sa, nonce, ke = findType(inner, PayloadSA), findType(inner, PayloadNonce), findType(inner, PayloadKE)
		if m.Header.ExchangeType != CREATE_CHILD_SA || m.Header.MessageID != 3 || sa == nil || nonce == nil || ke == nil {
			t.Errorf("incomplete retried IKE rekey request")
			return
		}
		props, err = DecodeSA(sa.Body)
		if err != nil || len(props) != 1 || props[0].Protocol != ProtoIKE || len(props[0].SPI) != 8 {
			t.Errorf("bad retried IKE rekey proposal: %#v, %v", props, err)
			return
		}
		group, _, err = DecodeKE(ke.Body)
		if err != nil || group != DH_ECP_256 || len(nonce.Body) == 0 || binary.BigEndian.Uint64(props[0].SPI) == 0 {
			t.Errorf("bad retried IKE rekey KE or nonce: %d, %v", group, err)
			return
		}
		responderDH, err := GenerateDH(group)
		if err != nil {
			t.Errorf("generate responder DH: %v", err)
			return
		}
		nr := []byte("responder nonce for IKE rekey")
		spiR := make([]byte, 8)
		binary.BigEndian.PutUint64(spiR, newSPIr)
		response, err = EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spiR, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: group}}}})},
			{Type: PayloadNonce, Body: EncodeNonce(nr)},
			{Type: PayloadKE, Body: EncodeKE(group, responderDH.PublicBytes())},
		})
		if err != nil {
			t.Errorf("encrypt rekey response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write rekey response: %v", err)
			return
		}

		n, addr, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read old IKE delete: %v", err)
			return
		}
		raw = append([]byte(nil), buf[4:n]...)
		m, err = DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode old IKE delete: %v", err)
			return
		}
		inner, err = DecryptMessage(suite, old.skei, raw, m)
		if err != nil {
			t.Errorf("decrypt old IKE delete: %v", err)
			return
		}
		d := findType(inner, PayloadD)
		if m.Header.SPIInitiator != oldSPIi || m.Header.SPIResponder != oldSPIr || m.Header.ExchangeType != INFORMATIONAL || m.Header.MessageID != 4 || d == nil {
			t.Errorf("unexpected old IKE delete")
			return
		}
		deletePayload, err := DecodeDelete(d.Body)
		if err != nil || deletePayload.Protocol != ProtoIKE || len(deletePayload.SPIs) != 0 {
			t.Errorf("bad old IKE delete: %#v, %v", deletePayload, err)
			return
		}
		response, err = EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, nil)
		if err != nil {
			t.Errorf("encrypt old IKE delete response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write old IKE delete response: %v", err)
		}
	}()

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()
	if err := s.RekeyIKE(); err != nil {
		t.Fatalf("RekeyIKE: %v", err)
	}
	<-peerDone
	current, retained := s.contexts()
	if current == old || current.spiR != newSPIr || current.suite.DHGroup != DH_ECP_256 || retained != nil {
		t.Fatalf("IKE contexts not promoted and retired: current=%#v old=%#v", current, retained)
	}
	if got := s.currentChild(); got.EncrID != child.EncrID || got.EncrKeyBits != child.EncrKeyBits || got.LocalSPI != child.LocalSPI || got.RemoteSPI != child.RemoteSPI || len(got.InboundKey) != 0 || len(got.OutboundKey) != 0 {
		t.Fatalf("Child SA changed during IKE rekey: %#v, want %#v", got, child)
	}
	if s.contextForHeader(&Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr}) != nil {
		t.Fatal("old IKE context is still retained")
	}
	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}

func TestSessionHandlesPeerIKERekey(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const oldSPIi = 0x0102030405060708
	const oldSPIr = 0x1112131415161718
	const newSPIi = 0x2122232425262728
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: oldSPIi, spiR: oldSPIr,
		skD: []byte("old IKE rekey SK_d material-------"), skei: make([]byte, 20), sker: make([]byte, 20)}
	child := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	s := &Session{mux: mux, current: old, Child: child, requests: make(chan *localRequest, 1)}
	if err := mux.RegisterIKE(oldSPIi); err != nil {
		t.Fatal(err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()

	// The proposal offers ranet's preferred Curve25519 first, while the KE
	// payload uses another supported offered group. RFC 7296 §1.3 requires
	// the responder to select the group actually used by KE.
	dh, err := GenerateDH(DH_ECP_256)
	if err != nil {
		t.Fatal(err)
	}
	ni := []byte("peer nonce for IKE rekey")
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, newSPIi)
	request, err := EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, MessageID: 0}, nil, []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{
			{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: []Transform{{Type: TransEncr, ID: 12, KeyLengthBits: 256}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: DH_ECP_256}}},
			{Number: 2, Protocol: ProtoIKE, SPI: spi, Transforms: ikeProposal().Transforms},
		})},
		{Type: PayloadNonce, Body: EncodeNonce(ni)},
		{Type: PayloadKE, Body: EncodeKE(DH_ECP_256, dh.PublicBytes())},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), mux.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw := append([]byte(nil), buf[4:n]...)
	response, err := DecodeMessage(responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.SPIInitiator != oldSPIi || response.Header.SPIResponder != oldSPIr || response.Header.Flags != FlagInitiator|FlagResponse {
		t.Fatalf("rekey response header = %#v", response.Header)
	}
	inner, err := DecryptMessage(suite, old.skei, responseRaw, response)
	if err != nil {
		t.Fatalf("decrypt old-context rekey response: %v", err)
	}
	sa, nonce, ke := findType(inner, PayloadSA), findType(inner, PayloadNonce), findType(inner, PayloadKE)
	if sa == nil || nonce == nil || ke == nil || findType(inner, PayloadTSi) != nil || findType(inner, PayloadTSr) != nil {
		t.Fatalf("invalid peer rekey response payloads: %#v", inner)
	}
	props, err := DecodeSA(sa.Body)
	if err != nil || len(props) != 1 || props[0].Number != 2 || props[0].Protocol != ProtoIKE || len(props[0].SPI) != 8 || len(props[0].Transforms) != 3 {
		t.Fatalf("invalid peer rekey response proposal: %#v, %v", props, err)
	}
	newSPIr := binary.BigEndian.Uint64(props[0].SPI)
	selectedProposal := props[0]
	selectedProposal.Number = 1
	selectedProposal.SPI = nil
	newSuite, err := suiteFromProposal(selectedProposal)
	if err != nil {
		t.Fatal(err)
	}
	group, public, err := DecodeKE(ke.Body)
	if err != nil || group != DH_ECP_256 || newSPIr == 0 || len(nonce.Body) == 0 {
		t.Fatalf("invalid peer rekey response KE: group=%d spi=%016x err=%v", group, newSPIr, err)
	}
	shared, err := dh.SharedSecret(public)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveRekeyedIKEKeys(old.suite.PRFID, old.skD, newSuite, shared, ni, nonce.Body, newSPIi, newSPIr)
	if err != nil {
		t.Fatal(err)
	}
	current, retained := s.contexts()
	if current == old || !current.responder || retained != old || current.suite != newSuite || current.spiI != newSPIi || current.spiR != newSPIr || string(current.skD) != string(keys.SKd) || string(current.skei) != string(keys.SKei) || string(current.sker) != string(keys.SKer) {
		t.Fatalf("peer rekey contexts = current %#v old %#v", current, retained)
	}
	if got := s.currentChild(); got.EncrID != child.EncrID || got.EncrKeyBits != child.EncrKeyBits || got.LocalSPI != child.LocalSPI || got.RemoteSPI != child.RemoteSPI || len(got.InboundKey) != 0 || len(got.OutboundKey) != 0 {
		t.Fatalf("Child SA changed during peer IKE rekey: %#v, want %#v", got, child)
	}

	request, err = EncryptMessage(current.suite, keys.SKei, Header{SPIInitiator: newSPIi, SPIResponder: newSPIr, ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), mux.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	n, _, err = peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw = append([]byte(nil), buf[4:n]...)
	response, err = DecodeMessage(responseRaw)
	if err != nil || response.Header.SPIInitiator != newSPIi || response.Header.SPIResponder != newSPIr || response.Header.Flags != FlagResponse {
		t.Fatalf("new-context response header = %#v, err=%v", response.Header, err)
	}
	if _, err := DecryptMessage(current.suite, keys.SKer, responseRaw, response); err != nil {
		t.Fatalf("decrypt new-context response: %v", err)
	}

	request, err = EncryptMessage(old.suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: INFORMATIONAL, MessageID: 1}, nil, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), mux.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	n, _, err = peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw = append([]byte(nil), buf[4:n]...)
	response, err = DecodeMessage(responseRaw)
	if err != nil || response.Header.SPIInitiator != oldSPIi || response.Header.SPIResponder != oldSPIr {
		t.Fatalf("old delete response header = %#v, err=%v", response.Header, err)
	}
	if _, err := DecryptMessage(old.suite, old.skei, responseRaw, response); err != nil {
		t.Fatalf("decrypt old delete response: %v", err)
	}
	_, retained = s.contexts()
	if retained != nil || s.contextForHeader(&Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr}) != nil {
		t.Fatal("old IKE context was not removed after peer delete")
	}

	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}

func TestPeerIKERekeyInvalidKERequestsPreferredGroup(t *testing.T) {
	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: spiI, spiR: spiR, skei: make([]byte, 20), sker: make([]byte, 20)}
	s := &Session{current: ctx}
	newSPI := make([]byte, 8)
	binary.BigEndian.PutUint64(newSPI, 0x2122232425262728)

	raw, err := s.handleIKERekey(ctx, 0, []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: newSPI, Transforms: ikeProposal().Transforms}})},
		{Type: PayloadNonce, Body: EncodeNonce([]byte("peer rekey nonce"))},
		{Type: PayloadKE, Body: EncodeKE(14, []byte{1})},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ctx.skei, raw, response)
	if err != nil {
		t.Fatal(err)
	}
	notifyPayload := findType(inner, PayloadN)
	if notifyPayload == nil {
		t.Fatalf("IKE rekey response has no notify: %#v", inner)
	}
	notify, err := DecodeNotify(notifyPayload.Body)
	if err != nil {
		t.Fatal(err)
	}
	if notify.Type != N_INVALID_KE_PAYLOAD || len(notify.Data) != 2 || binary.BigEndian.Uint16(notify.Data) != DH_CURVE25519 {
		t.Fatalf("IKE rekey notify = %#v, want INVALID_KE_PAYLOAD for group %d", notify, DH_CURVE25519)
	}
}

func TestSessionRekeyIKECollisionKeepsHigherNonceCandidate(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const oldSPIi = 0x0102030405060708
	const oldSPIr = 0x1112131415161718
	const peerSPIi = 0x2122232425262728
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: oldSPIi, spiR: oldSPIr, nextLocalMID: 2,
		skD: []byte("old IKE rekey SK_d material-------"), skei: make([]byte, 20), sker: make([]byte, 20)}
	localNonce := make([]byte, 32)
	for i := range localNonce {
		localNonce[i] = 2
	}
	peerNonce := make([]byte, 32)
	for i := range peerNonce {
		peerNonce[i] = 1
	}
	s := &Session{mux: mux, current: old, requests: make(chan *localRequest, 1), ikeRekeyNonce: func(n []byte) error {
		copy(n, localNonce)
		return nil
	}}
	if err := mux.RegisterIKE(oldSPIi); err != nil {
		t.Fatal(err)
	}

	peerDone := make(chan struct{})
	winnerSPIi := make(chan uint64, 1)
	go func() {
		defer close(peerDone)
		peer.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, addr, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read local rekey request: %v", err)
			return
		}
		localRaw := append([]byte(nil), buf[4:n]...)
		localRequest, err := DecodeMessage(localRaw)
		if err != nil {
			t.Errorf("decode local rekey request: %v", err)
			return
		}
		localInner, err := DecryptMessage(suite, old.skei, localRaw, localRequest)
		if err != nil {
			t.Errorf("decrypt local rekey request: %v", err)
			return
		}
		localSA, localNI, localKE := findType(localInner, PayloadSA), findType(localInner, PayloadNonce), findType(localInner, PayloadKE)
		if localSA == nil || localNI == nil || localKE == nil {
			t.Errorf("invalid local rekey request")
			return
		}
		localProps, err := DecodeSA(localSA.Body)
		if err != nil || len(localProps) != 1 {
			t.Errorf("invalid local rekey proposal: %v", err)
			return
		}
		localSPIi := binary.BigEndian.Uint64(localProps[0].SPI)
		winnerSPIi <- localSPIi
		localGroup, _, err := DecodeKE(localKE.Body)
		if err != nil || localGroup != DH_CURVE25519 || string(localNI.Body) != string(localNonce) {
			t.Errorf("local rekey nonce or KE = %x, group %d, err %v", localNI.Body, localGroup, err)
			return
		}

		peerDH, err := GenerateDH(DH_CURVE25519)
		if err != nil {
			t.Errorf("generate peer DH: %v", err)
			return
		}
		spi := make([]byte, 8)
		binary.BigEndian.PutUint64(spi, peerSPIi)
		collisionRequest, err := EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, MessageID: 0}, nil, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: DH_CURVE25519}}}})},
			{Type: PayloadNonce, Body: EncodeNonce(peerNonce)},
			{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, peerDH.PublicBytes())},
		})
		if err != nil {
			t.Errorf("build peer rekey request: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(collisionRequest), addr); err != nil {
			t.Errorf("write peer rekey request: %v", err)
			return
		}

		n, _, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read peer rekey response: %v", err)
			return
		}
		collisionRaw := append([]byte(nil), buf[4:n]...)
		collisionResponse, err := DecodeMessage(collisionRaw)
		if err != nil {
			t.Errorf("decode peer rekey response: %v", err)
			return
		}
		collisionInner, err := DecryptMessage(suite, old.skei, collisionRaw, collisionResponse)
		if err != nil {
			t.Errorf("decrypt peer rekey response: %v", err)
			return
		}
		collisionSA, collisionNR, collisionKE := findType(collisionInner, PayloadSA), findType(collisionInner, PayloadNonce), findType(collisionInner, PayloadKE)
		if collisionSA == nil || collisionNR == nil || collisionKE == nil {
			t.Errorf("invalid peer rekey response")
			return
		}
		collisionProps, err := DecodeSA(collisionSA.Body)
		if err != nil || len(collisionProps) != 1 {
			t.Errorf("invalid peer rekey proposal: %v", err)
			return
		}
		peerSPIr := binary.BigEndian.Uint64(collisionProps[0].SPI)
		_, responderPublic, err := DecodeKE(collisionKE.Body)
		if err != nil {
			t.Errorf("decode peer response KE: %v", err)
			return
		}
		shared, err := peerDH.SharedSecret(responderPublic)
		if err != nil {
			t.Errorf("derive peer shared secret: %v", err)
			return
		}
		collisionKeys, err := DeriveRekeyedIKEKeys(old.suite.PRFID, old.skD, suite, shared, peerNonce, collisionNR.Body, peerSPIi, peerSPIr)
		if err != nil {
			t.Errorf("derive collision keys: %v", err)
			return
		}
		if s.contextForHeader(&Header{SPIInitiator: peerSPIi, SPIResponder: peerSPIr}) == nil {
			t.Error("lower-nonce candidate is not routed while awaiting retirement")
			return
		}

		responderDH, err := GenerateDH(DH_CURVE25519)
		if err != nil {
			t.Errorf("generate local rekey responder DH: %v", err)
			return
		}
		spi = make([]byte, 8)
		binary.BigEndian.PutUint64(spi, 0x3132333435363738)
		localResponse, err := EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, Flags: FlagResponse, MessageID: localRequest.Header.MessageID}, nil, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: DH_CURVE25519}}}})},
			{Type: PayloadNonce, Body: EncodeNonce(localNonce)},
			{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, responderDH.PublicBytes())},
		})
		if err != nil {
			t.Errorf("build local rekey response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(localResponse), addr); err != nil {
			t.Errorf("write local rekey response: %v", err)
			return
		}

		n, _, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read loser delete: %v", err)
			return
		}
		deleteRaw := append([]byte(nil), buf[4:n]...)
		deleteMessage, err := DecodeMessage(deleteRaw)
		if err != nil {
			t.Errorf("decode loser delete: %v", err)
			return
		}
		deleteInner, err := DecryptMessage(suite, collisionKeys.SKer, deleteRaw, deleteMessage)
		deletePayload := findType(deleteInner, PayloadD)
		if err != nil || deletePayload == nil {
			t.Errorf("invalid loser delete: %v", err)
			return
		}
		deleteRequest, err := DecodeDelete(deletePayload.Body)
		if err != nil || deleteMessage.Header.SPIInitiator != peerSPIi || deleteMessage.Header.SPIResponder != peerSPIr || deleteRequest.Protocol != ProtoIKE {
			t.Errorf("loser delete = %#v, %#v, %v", deleteMessage.Header, deleteRequest, err)
			return
		}
		deleteResponse, err := EncryptMessage(suite, collisionKeys.SKei, Header{SPIInitiator: peerSPIi, SPIResponder: peerSPIr, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: deleteMessage.Header.MessageID}, nil, nil)
		if err != nil {
			t.Errorf("build loser delete response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(deleteResponse), addr); err != nil {
			t.Errorf("write loser delete response: %v", err)
			return
		}

		n, _, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read replaced-context delete: %v", err)
			return
		}
		oldDeleteRaw := append([]byte(nil), buf[4:n]...)
		oldDelete, err := DecodeMessage(oldDeleteRaw)
		if err != nil {
			t.Errorf("decode replaced-context delete: %v", err)
			return
		}
		oldDeleteInner, err := DecryptMessage(suite, old.skei, oldDeleteRaw, oldDelete)
		oldDeletePayload := findType(oldDeleteInner, PayloadD)
		if err != nil || oldDeletePayload == nil || oldDelete.Header.SPIInitiator != oldSPIi || oldDelete.Header.SPIResponder != oldSPIr {
			t.Errorf("invalid replaced-context delete: %#v, %v", oldDelete.Header, err)
			return
		}
		oldDeleteResponse, err := EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: oldDelete.Header.MessageID}, nil, nil)
		if err != nil {
			t.Errorf("build replaced-context delete response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(oldDeleteResponse), addr); err != nil {
			t.Errorf("write replaced-context delete response: %v", err)
		}
	}()

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()
	if err := s.RekeyIKE(); err != nil {
		t.Fatalf("RekeyIKE: %v", err)
	}
	<-peerDone
	localSPIi := <-winnerSPIi
	current, retained := s.contexts()
	s.stateMu.RLock()
	collision := s.collision
	s.stateMu.RUnlock()
	if current == old || current.spiI != localSPIi || retained != nil || collision != nil {
		t.Fatalf("collision contexts = current %#v old %#v collision %#v", current, retained, collision)
	}
	if s.contextForHeader(&Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr}) != nil {
		t.Fatal("replaced IKE context remains routed")
	}
	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}

func TestCompareIKENonces(t *testing.T) {
	tests := []struct {
		a, b []byte
		want int
	}{
		{[]byte{0x00, 0xff}, []byte{0x01, 0x00}, -1},
		{[]byte{0x80}, []byte{0x7f}, 1},
		{[]byte{0x42}, []byte{0x42}, 0},
		{[]byte{0x00, 0x01}, []byte{0x01}, -1},
		{[]byte{0xff}, []byte{0x01, 0x00}, 1},
	}
	for _, test := range tests {
		got := compareIKENonces(test.a, test.b)
		if (got < 0 && test.want < 0) || (got == 0 && test.want == 0) || (got > 0 && test.want > 0) {
			continue
		}
		t.Errorf("compareIKENonces(%x, %x) = %d, want sign %d", test.a, test.b, got, test.want)
	}
}

func TestLowestNonceSelectsRedundantExchange(t *testing.T) {
	tests := []struct {
		name                             string
		firstI, firstR, secondI, secondR byte
		firstLoses                       bool
	}{
		{"first initiator lowest", 1, 4, 2, 3, true},
		{"first responder lowest", 4, 1, 2, 3, true},
		{"second initiator lowest", 2, 4, 1, 3, false},
		{"second responder lowest", 2, 3, 4, 1, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := lowestNonceBelongsToFirst([]byte{test.firstI}, []byte{test.firstR}, []byte{test.secondI}, []byte{test.secondR})
			if got != test.firstLoses {
				t.Fatalf("firstLoses = %v, want %v", got, test.firstLoses)
			}
		})
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

func TestIKEAuthAuthenticatesBeforeChildFailure(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	_, localPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remotePublic, remotePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := PeerConfig{
		Organization:     "ranet-test",
		LocalCommonName:  "initiator",
		LocalSerial:      "1",
		LocalPrivateKey:  localPrivate,
		RemoteCommonName: "responder",
		RemoteSerial:     "2",
		RemotePublicKey:  remotePublic,
	}

	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	s := &Session{
		mux: mux,
		current: &ikeContext{
			suite: suite, spiI: spiI, spiR: spiR, nextLocalMID: 2,
			skei: make([]byte, 20), sker: make([]byte, 20),
			skD: make([]byte, 32), skpi: make([]byte, 32), skpr: make([]byte, 32),
		},
		requests: make(chan *localRequest, 1),
	}
	realMessage1 := []byte("test IKE_SA_INIT request")
	realMessage2 := []byte("test IKE_SA_INIT response")
	ni := make([]byte, 32)
	nr := make([]byte, 32)

	peerDone := make(chan error, 1)
	go func() {
		peerDone <- func() error {
			buf := make([]byte, 4096)
			peer.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, clientAddr, err := peer.ReadFromUDP(buf)
			if err != nil {
				return fmt.Errorf("read IKE_AUTH request: %w", err)
			}
			if n <= 4 {
				return fmt.Errorf("short marked IKE_AUTH request: %d bytes", n)
			}
			raw := append([]byte(nil), buf[4:n]...)
			request, err := DecodeMessage(raw)
			if err != nil {
				return fmt.Errorf("decode IKE_AUTH request: %w", err)
			}
			if request.Header.ExchangeType != IKE_AUTH || request.Header.MessageID != 1 {
				return fmt.Errorf("unexpected IKE_AUTH header: exchange=%d message-id=%d", request.Header.ExchangeType, request.Header.MessageID)
			}
			if _, err := DecryptMessage(suite, s.current.skei, raw, request); err != nil {
				return fmt.Errorf("decrypt IKE_AUTH request: %w", err)
			}

			idr := EncodeID(ID_DER_ASN1_DN, EncodeIdentityDN(cfg.Organization, cfg.RemoteCommonName, cfg.RemoteSerial))
			macedID := prf(suite.PRFID, s.current.skpr, idr)
			auth := BuildAuth(remotePrivate, concat(realMessage2, ni, macedID))
			response, err := EncryptMessage(suite, s.current.sker, Header{
				SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_AUTH,
				Flags: FlagResponse, MessageID: 1,
			}, nil, []RawPayload{
				{Type: PayloadIDr, Body: idr},
				{Type: PayloadAUTH, Body: auth},
				{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})},
			})
			if err != nil {
				return fmt.Errorf("encrypt IKE_AUTH response: %w", err)
			}
			if _, err := peer.WriteToUDP(withNonESPMarker(response), clientAddr); err != nil {
				return fmt.Errorf("write IKE_AUTH response: %w", err)
			}

			n, _, err = peer.ReadFromUDP(buf)
			if err != nil {
				return fmt.Errorf("read IKE Delete request: %w", err)
			}
			if n <= 4 {
				return fmt.Errorf("short marked IKE Delete request: %d bytes", n)
			}
			raw = append([]byte(nil), buf[4:n]...)
			deleteMessage, err := DecodeMessage(raw)
			if err != nil {
				return fmt.Errorf("decode IKE Delete request: %w", err)
			}
			if deleteMessage.Header.ExchangeType != INFORMATIONAL || deleteMessage.Header.MessageID != 2 {
				return fmt.Errorf("unexpected IKE Delete header: exchange=%d message-id=%d", deleteMessage.Header.ExchangeType, deleteMessage.Header.MessageID)
			}
			deleteInner, err := DecryptMessage(suite, s.current.skei, raw, deleteMessage)
			if err != nil {
				return fmt.Errorf("decrypt IKE Delete request: %w", err)
			}
			if len(deleteInner) != 1 || deleteInner[0].Type != PayloadD {
				return fmt.Errorf("IKE Delete inner payloads = %v, want one Delete", deleteInner)
			}
			deletePayload, err := DecodeDelete(deleteInner[0].Body)
			if err != nil {
				return fmt.Errorf("decode IKE Delete payload: %w", err)
			}
			if deletePayload.Protocol != ProtoIKE || len(deletePayload.SPIs) != 0 {
				return fmt.Errorf("IKE Delete = %+v, want protocol IKE and no SPIs", deletePayload)
			}

			deleteResponse, err := EncryptMessage(suite, s.current.sker, Header{
				SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL,
				Flags: FlagResponse, MessageID: 2,
			}, nil, nil)
			if err != nil {
				return fmt.Errorf("encrypt IKE Delete response: %w", err)
			}
			if _, err := peer.WriteToUDP(withNonESPMarker(deleteResponse), clientAddr); err != nil {
				return fmt.Errorf("write IKE Delete response: %w", err)
			}
			return nil
		}()
	}()

	err = s.completeIKEAuth(cfg, realMessage1, realMessage2, ni, nr)
	if err == nil || err.Error() != "ike: Child SA rejected: notify type 14" {
		t.Fatalf("completeIKEAuth error = %v, want authenticated Child SA rejection", err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
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
	const spiR = 0x1122334455667788
	req := encodeTestMessage(t, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: 3}, nil)

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
		resp := withNonESPMarker(encodeTestMessage(t, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: 3}, nil))
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
		mux: mux,
		current: &ikeContext{suite: suite, spiI: spiI, spiR: spiR, nextLocalMID: 2,
			skei: make([]byte, 20), sker: make([]byte, 20)},
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
			if _, err := DecryptMessage(suite, s.current.skei, raw, m); err != nil {
				t.Errorf("decrypt request: %v", err)
				return
			}
			ids = append(ids, m.Header.MessageID)
			response, err := EncryptMessage(suite, s.current.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: m.Header.ExchangeType, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, nil)
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
	go func() { runDone <- s.Run(context.Background()) }()
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

func TestSessionRunUsesOldIKEContext(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	current := &ikeContext{suite: suite, spiI: 0x0102030405060708, spiR: 0x1112131415161718, skei: make([]byte, 20), sker: make([]byte, 20)}
	old := &ikeContext{suite: suite, spiI: 0x2122232425262728, spiR: 0x3132333435363738, skei: []byte("old initiator key---"), sker: []byte("old responder key---")}
	s := &Session{mux: mux, current: current, old: old, requests: make(chan *localRequest, 1)}
	if err := mux.RegisterIKE(current.spiI); err != nil {
		t.Fatal(err)
	}
	if err := mux.RegisterIKE(old.spiI); err != nil {
		t.Fatal(err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()
	request, err := EncryptMessage(old.suite, old.sker, Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: INFORMATIONAL, MessageID: 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), mux.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw := append([]byte(nil), buf[4:n]...)
	response, err := DecodeMessage(responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.SPIInitiator != old.spiI || response.Header.SPIResponder != old.spiR {
		t.Fatalf("response SPI pair = %016x/%016x, want old %016x/%016x", response.Header.SPIInitiator, response.Header.SPIResponder, old.spiI, old.spiR)
	}
	if _, err := DecryptMessage(old.suite, old.skei, responseRaw, response); err != nil {
		t.Fatalf("decrypt old-context response: %v", err)
	}
	oldMID, currentMID := s.nextPeerMessageID(old), s.nextPeerMessageID(current)
	if oldMID != 1 || currentMID != 0 {
		t.Fatalf("peer message IDs old/current = %d/%d, want 1/0", oldMID, currentMID)
	}
	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}
