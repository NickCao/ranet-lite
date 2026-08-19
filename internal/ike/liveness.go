package ike

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

const (
	dpdInterval         = 10 * time.Second
	requestPollInterval = 100 * time.Millisecond
)

type localRequest struct {
	exchange ExchangeType
	inner    []RawPayload
	result   chan requestResult
	dpd      bool
}

type requestResult struct {
	inner []RawPayload
	err   error
}

type pendingRequest struct {
	localRequest
	context  *ikeContext
	msgID    uint32
	raw      []byte
	attempts int
	deadline time.Time
}

func findType(payloads []RawPayload, t PayloadType) *RawPayload {
	for i := range payloads {
		if payloads[i].Type == t {
			return &payloads[i]
		}
	}
	return nil
}

// Run is the sole post-handshake IKE receiver. It dispatches authenticated
// peer requests and correlated local responses while also driving DPD.
func (s *Session) Run() error {
	lastAuthenticated := time.Now()
	var pending *pendingRequest
	for {
		if nanos := s.lastTraffic.Load(); nanos != 0 {
			if traffic := time.Unix(0, nanos); traffic.After(lastAuthenticated) {
				lastAuthenticated = traffic
			}
		}
		if pending == nil {
			select {
			case req := <-s.requests:
				var err error
				pending, err = s.startRequest(req)
				if err != nil {
					req.result <- requestResult{err: err}
				}
			default:
			}
		}

		deadline := lastAuthenticated.Add(dpdInterval)
		if pending != nil && pending.deadline.Before(deadline) {
			deadline = pending.deadline
		}
		// Mux has no selectable receive channel. Polling avoids another receiver.
		if poll := time.Now().Add(requestPollInterval); poll.Before(deadline) {
			deadline = poll
		}
		raw, err := s.mux.RecvIKEUntil(deadline)
		if err != nil {
			if !transport.IsTimeout(err) {
				if pending != nil {
					pending.result <- requestResult{err: err}
				}
				return err
			}
			if pending != nil && !time.Now().Before(pending.deadline) {
				if pending.attempts == maxRetransmits {
					if pending.dpd {
						s.mux.Close()
						return fmt.Errorf("ike: DPD failed: no response after %d attempts", maxRetransmits)
					}
					pending.result <- requestResult{err: fmt.Errorf("no response after %d attempts", maxRetransmits)}
					pending = nil
				} else if err := s.sendPending(pending); err != nil {
					if pending.dpd {
						s.mux.Close()
						return fmt.Errorf("ike: DPD failed: %w", err)
					}
					pending.result <- requestResult{err: err}
					pending = nil
				}
				continue
			}
			if pending == nil && !time.Now().Before(lastAuthenticated.Add(dpdInterval)) {
				pending, err = s.startRequest(&localRequest{exchange: INFORMATIONAL, result: make(chan requestResult, 1), dpd: true})
				if err != nil {
					s.mux.Close()
					return fmt.Errorf("ike: DPD failed: %w", err)
				}
			}
			continue
		}
		if s.dispatch(raw, &pending) {
			lastAuthenticated = time.Now()
		}
	}
}

// request starts a serialized local exchange through Run. Future Child SA
// rekey support uses this path rather than receiving directly from the mux.
func (s *Session) request(exchange ExchangeType, inner []RawPayload) ([]RawPayload, error) {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	req := &localRequest{exchange: exchange, inner: inner, result: make(chan requestResult, 1)}
	s.requests <- req
	result := <-req.result
	return result.inner, result.err
}

func (s *Session) startRequest(req *localRequest) (*pendingRequest, error) {
	msgID := s.current.nextLocalMID
	s.current.nextLocalMID++
	hdr := Header{SPIInitiator: s.current.spiI, SPIResponder: s.current.spiR, ExchangeType: req.exchange, Flags: FlagInitiator, MessageID: msgID}
	raw, err := EncryptMessage(s.current.suite, s.current.skei, hdr, nil, req.inner)
	if err != nil {
		return nil, err
	}
	pending := &pendingRequest{localRequest: *req, context: s.current, msgID: msgID, raw: raw}
	if err := s.sendPending(pending); err != nil {
		return nil, err
	}
	return pending, nil
}

func (s *Session) sendPending(pending *pendingRequest) error {
	if err := s.mux.SendIKE(pending.raw); err != nil {
		return err
	}
	pending.attempts++
	pending.deadline = time.Now().Add(requestTimeout)
	return nil
}

func (s *Session) dispatch(raw []byte, pending **pendingRequest) bool {
	hdr, err := decodeHeader(raw)
	if err != nil {
		return false
	}
	ctx := s.contextForHeader(hdr)
	if ctx == nil {
		return false
	}
	outer, err := DecodeMessage(raw)
	if err != nil {
		return false
	}
	inner, err := DecryptMessage(ctx.suite, ctx.sker, raw, outer)
	if err != nil {
		return false
	}
	if hdr.IsResponse() && !hdr.IsInitiator() {
		if current := *pending; current != nil && current.context == ctx && hdr.MessageID == current.msgID && hdr.ExchangeType == current.exchange {
			current.result <- requestResult{inner: inner}
			*pending = nil
			return true
		}
		return false
	}
	if hdr.IsInitiator() || hdr.IsResponse() {
		return false
	}
	if hdr.MessageID != ctx.nextPeerMID {
		if ctx.nextPeerMID > 0 && hdr.MessageID == ctx.nextPeerMID-1 && ctx.lastPeerResponseID == hdr.MessageID {
			if err := s.mux.SendIKE(ctx.lastPeerResponse); err != nil {
				s.mux.Close()
			}
		}
		return true
	}
	response, err := s.handleRequest(ctx, hdr, inner)
	if err != nil {
		if response != nil {
			_ = s.mux.SendIKE(response)
		}
		s.mux.Close()
		return true
	}
	if err := s.mux.SendIKE(response); err != nil {
		s.mux.Close()
		return true
	}
	ctx.lastPeerResponseID = hdr.MessageID
	ctx.lastPeerResponse = response
	ctx.nextPeerMID++
	return true
}

func (s *Session) contextForHeader(hdr *Header) *ikeContext {
	if hdr.SPIInitiator == s.current.spiI && hdr.SPIResponder == s.current.spiR {
		return s.current
	}
	if s.old != nil && hdr.SPIInitiator == s.old.spiI && hdr.SPIResponder == s.old.spiR {
		return s.old
	}
	return nil
}

func (s *Session) handleRequest(ctx *ikeContext, hdr *Header, inner []RawPayload) ([]byte, error) {
	if hdr.ExchangeType == INFORMATIONAL {
		for _, p := range inner {
			if p.Type != PayloadD {
				continue
			}
			d, err := DecodeDelete(p.Body)
			if err != nil {
				return nil, err
			}
			if d.Protocol == ProtoIKE {
				response, err := s.response(ctx, hdr.MessageID, INFORMATIONAL, nil)
				if err != nil {
					return nil, err
				}
				return response, fmt.Errorf("peer deleted IKE SA")
			}
			child := s.currentChild()
			retiring := s.retiringChild()
			for _, spi := range d.SPIs {
				if d.Protocol == ProtoESP && len(spi) == 4 && binary.BigEndian.Uint32(spi) == child.RemoteSPI {
					local := make([]byte, 4)
					binary.BigEndian.PutUint32(local, child.LocalSPI)
					response, err := s.response(ctx, hdr.MessageID, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{local}})}})
					if err != nil {
						return nil, err
					}
					return response, fmt.Errorf("peer deleted Child SA")
				}
				if d.Protocol == ProtoESP && len(spi) == 4 && binary.BigEndian.Uint32(spi) == retiring.RemoteSPI {
					local := make([]byte, 4)
					binary.BigEndian.PutUint32(local, retiring.LocalSPI)
					response, err := s.response(ctx, hdr.MessageID, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{local}})}})
					if err != nil {
						return nil, err
					}
					if err := s.retireChild(retiring.RemoteSPI); err != nil {
						return nil, err
					}
					return response, nil
				}
			}
		}
		return s.response(ctx, hdr.MessageID, INFORMATIONAL, nil)
	}
	if hdr.ExchangeType == CREATE_CHILD_SA {
		return s.handleChildRekey(ctx, hdr.MessageID, inner)
	}
	return s.response(ctx, hdr.MessageID, INFORMATIONAL, nil)
}

func (s *Session) handleChildRekey(ctx *ikeContext, msgID uint32, inner []RawPayload) ([]byte, error) {
	var rekey Notify
	var sa, nonce, tsi, tsr *RawPayload
	for i := range inner {
		switch inner[i].Type {
		case PayloadN:
			n, err := DecodeNotify(inner[i].Body)
			if err != nil {
				return nil, err
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
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_CHILD_SA_NOT_FOUND)
	}
	if sa == nil || nonce == nil || tsi == nil || tsr == nil || len(nonce.Body) == 0 || findType(inner, PayloadKE) != nil {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	props, err := DecodeSA(sa.Body)
	if err != nil || len(props) != 1 || len(props[0].SPI) != 4 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	encr, ok := props[0].ChosenTransform(TransEncr)
	if !ok || encr.ID != child.EncrID || encr.KeyLengthBits != child.EncrKeyBits {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	var spi [4]byte
	for binary.BigEndian.Uint32(spi[:]) == 0 {
		if _, err := rand.Read(spi[:]); err != nil {
			return nil, err
		}
	}
	nr := make([]byte, 32)
	if _, err := rand.Read(nr); err != nil {
		return nil, err
	}
	initKey, respKey, err := ChildSAKeymat(ctx.suite.PRFID, ctx.skD, nonce.Body, nr, encr.ID, encr.KeyLengthBits)
	if err != nil {
		return nil, err
	}
	replacement := ChildSA{EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits, LocalSPI: binary.BigEndian.Uint32(spi[:]), RemoteSPI: binary.BigEndian.Uint32(props[0].SPI), InboundKey: initKey, OutboundKey: respKey}
	if err := s.replaceChild(replacement); err != nil {
		return nil, err
	}
	response := Proposal{Number: props[0].Number, Protocol: ProtoESP, SPI: spi[:], Transforms: []Transform{{Type: TransEncr, ID: encr.ID, KeyLengthBits: encr.KeyLengthBits}, {Type: TransESN, ID: ESN_NO}}}
	return s.response(ctx, msgID, CREATE_CHILD_SA, []RawPayload{{Type: PayloadSA, Body: EncodeSA([]Proposal{response})}, {Type: PayloadNonce, Body: EncodeNonce(nr)}, {Type: PayloadTSi, Body: tsi.Body}, {Type: PayloadTSr, Body: tsr.Body}})
}

func (s *Session) response(ctx *ikeContext, msgID uint32, exchange ExchangeType, inner []RawPayload) ([]byte, error) {
	hdr := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: exchange, Flags: FlagInitiator | FlagResponse, MessageID: msgID}
	raw, err := EncryptMessage(ctx.suite, ctx.skei, hdr, nil, inner)
	if err != nil {
		return nil, fmt.Errorf("ike: build response: %w", err)
	}
	return raw, nil
}

func (s *Session) responseNotify(ctx *ikeContext, msgID uint32, exchange ExchangeType, notifyType NotifyType) ([]byte, error) {
	return s.response(ctx, msgID, exchange, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: notifyType})}})
}
