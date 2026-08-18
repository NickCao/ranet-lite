package ike

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

const dpdInterval = 10 * time.Second

func findType(payloads []RawPayload, t PayloadType) *RawPayload {
	for i := range payloads {
		if payloads[i].Type == t {
			return &payloads[i]
		}
	}
	return nil
}

// Run is the sole post-handshake IKE receiver. It handles peer requests and
// probes with an encrypted empty INFORMATIONAL exchange after an idle period.
func (s *Session) Run() error {
	lastAuthenticated := time.Now()
	for {
		if nanos := s.lastTraffic.Load(); nanos != 0 {
			if traffic := time.Unix(0, nanos); traffic.After(lastAuthenticated) {
				lastAuthenticated = traffic
			}
		}
		raw, err := s.mux.RecvIKEUntil(lastAuthenticated.Add(dpdInterval))
		if err != nil {
			if !transport.IsTimeout(err) {
				return err
			}
			if err := s.probe(); err != nil {
				s.mux.Close()
				return fmt.Errorf("ike: DPD failed: %w", err)
			}
			lastAuthenticated = time.Now()
			continue
		}
		if s.handle(raw) {
			lastAuthenticated = time.Now()
		}
	}
}

func (s *Session) handle(raw []byte) bool {
	hdr, err := decodeHeader(raw)
	if err != nil || hdr.SPIInitiator != s.spiI || hdr.SPIResponder != s.spiR || hdr.IsInitiator() || hdr.IsResponse() {
		return false
	}
	outer, err := DecodeMessage(raw)
	if err != nil {
		return false
	}
	inner, err := DecryptMessage(s.suite, s.sker, raw, outer)
	if err != nil {
		return false
	}
	if err := s.handleRequest(hdr, inner); err != nil {
		s.mux.Close()
	}
	return true
}

func (s *Session) handleRequest(hdr *Header, inner []RawPayload) error {
	if hdr.ExchangeType == INFORMATIONAL {
		for _, p := range inner {
			if p.Type != PayloadD {
				continue
			}
			d, err := DecodeDelete(p.Body)
			if err != nil {
				return err
			}
			if d.Protocol == ProtoIKE {
				if err := s.respondEmpty(hdr.MessageID); err != nil {
					return err
				}
				return fmt.Errorf("peer deleted IKE SA")
			}
			child := s.currentChild()
			for _, spi := range d.SPIs {
				if d.Protocol == ProtoESP && len(spi) == 4 && binary.BigEndian.Uint32(spi) == child.RemoteSPI {
					// RFC 7296 section 1.4.1: return the paired inbound SPI.
					local := make([]byte, 4)
					binary.BigEndian.PutUint32(local, child.LocalSPI)
					if err := s.respond(hdr.MessageID, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{local}})}}); err != nil {
						return err
					}
					return fmt.Errorf("peer deleted Child SA")
				}
			}
		}
		return s.respondEmpty(hdr.MessageID)
	}
	if hdr.ExchangeType == CREATE_CHILD_SA {
		return s.handleChildRekey(hdr.MessageID, inner)
	}
	return s.respondEmpty(hdr.MessageID)
}

func (s *Session) handleChildRekey(msgID uint32, inner []RawPayload) error {
	var rekey Notify
	var sa, nonce, tsi, tsr *RawPayload
	for i := range inner {
		switch inner[i].Type {
		case PayloadN:
			n, err := DecodeNotify(inner[i].Body)
			if err != nil {
				return err
			}
			if n.Type == N_REKEY_SA {
				rekey = n
			}
		case PayloadSA:
			sa = &inner[i]
		case PayloadNonce:
			nonce = &inner[i]
		case PayloadTSi:
			tsi = &inner[i]
		case PayloadTSr:
			tsr = &inner[i]
		}
	}
	child := s.currentChild()
	if rekey.Type != N_REKEY_SA || rekey.Protocol != ProtoESP || len(rekey.SPI) != 4 || binary.BigEndian.Uint32(rekey.SPI) != child.RemoteSPI {
		return s.respondNotify(msgID, CREATE_CHILD_SA, N_CHILD_SA_NOT_FOUND)
	}
	// This minimal profile negotiates no Child-SA PFS, matching IKE_AUTH.
	if sa == nil || nonce == nil || tsi == nil || tsr == nil || len(nonce.Body) == 0 || findType(inner, PayloadKE) != nil {
		return s.respondNotify(msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	props, err := DecodeSA(sa.Body)
	if err != nil || len(props) != 1 || len(props[0].SPI) != 4 {
		return s.respondNotify(msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	encr, ok := props[0].ChosenTransform(TransEncr)
	if !ok || encr.ID != child.EncrID || encr.KeyLengthBits != child.EncrKeyBits {
		return s.respondNotify(msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	var spi [4]byte
	for binary.BigEndian.Uint32(spi[:]) == 0 {
		if _, err := rand.Read(spi[:]); err != nil {
			return err
		}
	}
	nr := make([]byte, 32)
	if _, err := rand.Read(nr); err != nil {
		return err
	}
	initKey, respKey, err := ChildSAKeymat(s.suite.PRFID, s.skD, nonce.Body, nr, encr.ID, encr.KeyLengthBits)
	if err != nil {
		return err
	}
	// The peer initiated this exchange, so initiator->responder keying is inbound.
	replacement := ChildSA{EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits, LocalSPI: binary.BigEndian.Uint32(spi[:]), RemoteSPI: binary.BigEndian.Uint32(props[0].SPI), InboundKey: initKey, OutboundKey: respKey}
	if err := s.replaceChild(replacement); err != nil {
		return err
	}
	response := Proposal{Number: props[0].Number, Protocol: ProtoESP, SPI: spi[:], Transforms: []Transform{{Type: TransEncr, ID: encr.ID, KeyLengthBits: encr.KeyLengthBits}, {Type: TransESN, ID: ESN_NO}}}
	return s.respond(msgID, CREATE_CHILD_SA, []RawPayload{{Type: PayloadSA, Body: EncodeSA([]Proposal{response})}, {Type: PayloadNonce, Body: EncodeNonce(nr)}, {Type: PayloadTSi, Body: tsi.Body}, {Type: PayloadTSr, Body: tsr.Body}})
}

func (s *Session) probe() error {
	msgID := s.selfMID
	s.selfMID++
	hdr := Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: msgID}
	req, err := EncryptMessage(s.suite, s.skei, hdr, nil, nil)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < maxRetransmits; attempt++ {
		if err := s.mux.SendIKE(req); err != nil {
			return err
		}
		deadline := time.Now().Add(requestTimeout)
		for {
			raw, err := s.mux.RecvIKEUntil(deadline)
			if err != nil {
				break
			}
			h, err := decodeHeader(raw)
			if err != nil || h.SPIInitiator != s.spiI || h.SPIResponder != s.spiR {
				continue
			}
			if h.IsResponse() && h.MessageID == msgID && h.ExchangeType == INFORMATIONAL {
				m, err := DecodeMessage(raw)
				if err == nil {
					_, err = DecryptMessage(s.suite, s.sker, raw, m)
				}
				if err == nil {
					return nil
				}
				continue
			}
			if !h.IsInitiator() && !h.IsResponse() {
				if m, err := DecodeMessage(raw); err == nil {
					if inner, err := DecryptMessage(s.suite, s.sker, raw, m); err == nil {
						if err := s.handleRequest(h, inner); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return fmt.Errorf("no response after %d attempts", maxRetransmits)
}

func (s *Session) respond(msgID uint32, exchange ExchangeType, inner []RawPayload) error {
	hdr := Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: exchange, Flags: FlagInitiator | FlagResponse, MessageID: msgID}
	raw, err := EncryptMessage(s.suite, s.skei, hdr, nil, inner)
	if err != nil {
		return fmt.Errorf("ike: build response: %w", err)
	}
	return s.mux.SendIKE(raw)
}

func (s *Session) respondEmpty(msgID uint32) error { return s.respond(msgID, INFORMATIONAL, nil) }

func (s *Session) respondNotify(msgID uint32, exchange ExchangeType, notifyType NotifyType) error {
	return s.respond(msgID, exchange, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: notifyType})}})
}
