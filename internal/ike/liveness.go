package ike

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/big"
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
	context  *ikeContext
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

type rekeySchedule struct {
	name     string
	interval time.Duration
	run      func() error
	timer    *time.Timer
	deadline time.Time
	due      bool
	failures uint
}

type rekeyScheduleResult struct {
	schedule *rekeySchedule
	err      error
}

func findType(payloads []RawPayload, t PayloadType) *RawPayload {
	for i := range payloads {
		if payloads[i].Type == t {
			return &payloads[i]
		}
	}
	return nil
}

func randomRekeyJitter(max time.Duration) (time.Duration, error) {
	if max == 0 {
		return 0, nil
	}
	limit := new(big.Int).Add(big.NewInt(int64(max)), big.NewInt(1))
	v, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return 0, err
	}
	return time.Duration(v.Int64()), nil
}

func (s *Session) rekeyDelay(interval time.Duration) (time.Duration, error) {
	source := s.rekeyJitterSource
	if source == nil {
		source = randomRekeyJitter
	}
	jitter, err := source(s.rekeyJitter)
	if err != nil {
		return 0, fmt.Errorf("ike: generate rekey jitter: %w", err)
	}
	if jitter < 0 || jitter > s.rekeyJitter {
		return 0, fmt.Errorf("ike: invalid rekey jitter %s", jitter)
	}
	delay := interval - s.rekeyMargin - jitter
	if delay <= 0 {
		return 0, fmt.Errorf("ike: nonpositive rekey delay")
	}
	return delay, nil
}

func (s *Session) rekeyRetryDelay(failures uint) time.Duration {
	delay := s.rekeyRetryInitial
	for failures > 1 {
		if delay >= s.rekeyRetryMax/2 {
			return s.rekeyRetryMax
		}
		delay *= 2
		failures--
	}
	return delay
}

func (s *Session) newRekeySchedule(name string, interval time.Duration, run func() error) (*rekeySchedule, error) {
	if interval <= 0 {
		return nil, nil
	}
	delay, err := s.rekeyDelay(interval)
	if err != nil {
		return nil, err
	}
	return &rekeySchedule{name: name, interval: interval, run: run, timer: time.NewTimer(delay), deadline: time.Now().Add(delay)}, nil
}

func (r *rekeySchedule) poll() {
	select {
	case <-r.timer.C:
		r.deadline = time.Time{}
		r.due = true
	default:
	}
}

func (r *rekeySchedule) reset(delay time.Duration) {
	r.timer.Reset(delay)
	r.deadline = time.Now().Add(delay)
}

func nextDueRekey(schedules []*rekeySchedule, running *rekeySchedule) *rekeySchedule {
	if running != nil {
		return nil
	}
	for _, schedule := range schedules {
		if schedule.due {
			schedule.due = false
			return schedule
		}
	}
	return nil
}

// Run is the sole post-handshake IKE receiver. It dispatches authenticated
// peer requests and correlated local responses while also driving DPD.
func (s *Session) Run(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = s.mux.Close() })
	defer stop()
	lastAuthenticated := time.Now()
	if s.rekeyRetryInitial == 0 && s.rekeyRetryMax == 0 {
		s.rekeyRetryInitial = 5 * time.Second
		s.rekeyRetryMax = 5 * time.Minute
	}
	var pending *pendingRequest
	var schedules []*rekeySchedule
	childSchedule, err := s.newRekeySchedule("Child SA", s.childRekeyInterval, s.RekeyChild)
	if err != nil {
		return err
	}
	if childSchedule != nil {
		defer childSchedule.timer.Stop()
		schedules = append(schedules, childSchedule)
	}
	ikeSchedule, err := s.newRekeySchedule("IKE SA", s.ikeRekeyInterval, s.RekeyIKE)
	if err != nil {
		return err
	}
	if ikeSchedule != nil {
		defer ikeSchedule.timer.Stop()
		schedules = append(schedules, ikeSchedule)
	}
	rekeyResult := make(chan rekeyScheduleResult, 1)
	var running *rekeySchedule
	startRekey := func(schedule *rekeySchedule) {
		running = schedule
		slog.Info("ike scheduled rekey starting", "sa", schedule.name)
		go func() { rekeyResult <- rekeyScheduleResult{schedule, schedule.run()} }()
	}
	startDueRekey := func() {
		if schedule := nextDueRekey(schedules, running); schedule != nil {
			startRekey(schedule)
		}
	}
	for {
		select {
		case result := <-rekeyResult:
			if result.err != nil {
				result.schedule.failures++
				delay := s.rekeyRetryDelay(result.schedule.failures)
				result.schedule.reset(delay)
				slog.Warn("ike scheduled rekey failed; retrying", "sa", result.schedule.name, "err", result.err, "retry_in", delay)
				running = nil
				startDueRekey()
				continue
			}
			slog.Info("ike scheduled rekey completed", "sa", result.schedule.name)
			result.schedule.failures = 0
			delay, err := s.rekeyDelay(result.schedule.interval)
			if err != nil {
				return err
			}
			result.schedule.reset(delay)
			running = nil
			startDueRekey()
		default:
		}
		for _, schedule := range schedules {
			schedule.poll()
		}
		startDueRekey()
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
		for _, schedule := range schedules {
			if !schedule.deadline.IsZero() && schedule.deadline.Before(deadline) {
				deadline = schedule.deadline
			}
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
	return s.requestLocked(exchange, inner)
}

// requestLocked sends a local request while requestMu is held.
func (s *Session) requestLocked(exchange ExchangeType, inner []RawPayload) ([]RawPayload, error) {
	return s.requestOnLocked(s.currentContext(), exchange, inner)
}

func (s *Session) requestOnLocked(context *ikeContext, exchange ExchangeType, inner []RawPayload) ([]RawPayload, error) {
	req := &localRequest{exchange: exchange, inner: inner, context: context, result: make(chan requestResult, 1)}
	s.requests <- req
	result := <-req.result
	return result.inner, result.err
}

func (s *Session) startRequest(req *localRequest) (*pendingRequest, error) {
	context := req.context
	if context == nil {
		context = s.currentContext()
	}
	msgID := context.nextLocalMID
	context.nextLocalMID++
	flags := uint8(0)
	if !context.responder {
		flags = FlagInitiator
	}
	hdr := Header{SPIInitiator: context.spiI, SPIResponder: context.spiR, ExchangeType: req.exchange, Flags: flags, MessageID: msgID}
	raw, err := context.encrypt(context.localEncryptionKey(), hdr, nil, req.inner)
	if err != nil {
		return nil, err
	}
	pending := &pendingRequest{localRequest: *req, context: context, msgID: msgID, raw: raw}
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
	inner, err := DecryptMessage(ctx.suite, ctx.peerEncryptionKey(), raw, outer)
	if err != nil {
		return false
	}
	if hdr.IsResponse() && hdr.IsInitiator() == ctx.responder {
		if current := *pending; current != nil && current.context == ctx && hdr.MessageID == current.msgID && hdr.ExchangeType == current.exchange {
			current.result <- requestResult{inner: inner}
			*pending = nil
			return true
		}
		return false
	}
	if hdr.IsInitiator() != ctx.responder || hdr.IsResponse() {
		return false
	}
	s.stateMu.RLock()
	nextPeerMID := ctx.nextPeerMID
	lastPeerResponseID := ctx.lastPeerResponseID
	lastPeerResponse := ctx.lastPeerResponse
	s.stateMu.RUnlock()
	if hdr.MessageID != nextPeerMID {
		if nextPeerMID > 0 && hdr.MessageID == nextPeerMID-1 && lastPeerResponseID == hdr.MessageID {
			if err := s.mux.SendIKE(lastPeerResponse); err != nil {
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
	s.stateMu.Lock()
	ctx.lastPeerResponseID = hdr.MessageID
	ctx.lastPeerResponse = response
	ctx.nextPeerMID++
	s.stateMu.Unlock()
	if err := s.mux.SendIKE(response); err != nil {
		s.mux.Close()
		return true
	}
	return true
}

func (s *Session) contextForHeader(hdr *Header) *ikeContext {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if hdr.SPIInitiator == s.current.spiI && hdr.SPIResponder == s.current.spiR {
		return s.current
	}
	if s.old != nil && hdr.SPIInitiator == s.old.spiI && hdr.SPIResponder == s.old.spiR {
		return s.old
	}
	if s.collision != nil && hdr.SPIInitiator == s.collision.spiI && hdr.SPIResponder == s.collision.spiR {
		return s.collision
	}
	return nil
}

func (s *Session) handleRequest(ctx *ikeContext, hdr *Header, inner []RawPayload) ([]byte, error) {
	for _, payload := range inner {
		if payload.Critical && !supportedPayloadType(payload.Type) {
			return s.responseNotifyData(ctx, hdr.MessageID, hdr.ExchangeType, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(payload.Type)})
		}
	}
	if hdr.ExchangeType == INFORMATIONAL {
		for _, p := range inner {
			if p.Type != PayloadD {
				continue
			}
			d, err := DecodeDelete(p.Body)
			if err != nil {
				response, responseErr := s.responseNotify(ctx, hdr.MessageID, INFORMATIONAL, N_INVALID_SYNTAX)
				if responseErr != nil {
					return nil, responseErr
				}
				return response, err
			}
			if d.Protocol == ProtoIKE {
				response, err := s.response(ctx, hdr.MessageID, INFORMATIONAL, nil)
				if err != nil {
					return nil, err
				}
				if s.removeRetainedContext(ctx) {
					s.mux.UnregisterIKE(ctx.spiI)
					return response, nil
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
		if sa := findType(inner, PayloadSA); sa != nil {
			props, err := DecodeSA(sa.Body)
			if err == nil && len(props) == 1 && props[0].Protocol == ProtoIKE {
				return s.handleIKERekey(ctx, hdr.MessageID, inner)
			}
		}
		return s.handleChildRekey(ctx, hdr.MessageID, inner)
	}
	response, err := s.responseNotify(ctx, hdr.MessageID, hdr.ExchangeType, N_INVALID_SYNTAX)
	if err != nil {
		return nil, err
	}
	return response, fmt.Errorf("ike: unsupported exchange type %d", hdr.ExchangeType)
}

func supportedPayloadType(payloadType PayloadType) bool {
	switch payloadType {
	case PayloadSA, PayloadKE, PayloadIDi, PayloadIDr, PayloadAUTH, PayloadNonce, PayloadN, PayloadD, PayloadTSi, PayloadTSr:
		return true
	default:
		return false
	}
}

func (s *Session) handleChildRekey(ctx *ikeContext, msgID uint32, inner []RawPayload) ([]byte, error) {
	if s.childRekeying.Load() {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	var rekey Notify
	payloads, err := decodeChildExchangePayloads(inner)
	if err != nil {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	for _, notify := range payloads.notifies {
		if notify.Type == N_REKEY_SA {
			rekey = notify
		}
	}
	child := s.currentChild()
	if rekey.Type != N_REKEY_SA || rekey.Protocol != ProtoESP || len(rekey.SPI) != 4 || binary.BigEndian.Uint32(rekey.SPI) != child.RemoteSPI {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_CHILD_SA_NOT_FOUND)
	}
	if err := validateFullRangeSelectors(payloads.tsi, payloads.tsr); err != nil {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	p, encr, remoteSPI, err := decodeChildProposal(payloads.sa.Body, &child)
	if err != nil {
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
	initKey, respKey, err := ChildSAKeymat(ctx.suite.PRFID, ctx.skD, payloads.nonce.Body, nr, encr.ID, encr.KeyLengthBits)
	if err != nil {
		return nil, err
	}
	replacement := ChildSA{EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits, LocalSPI: binary.BigEndian.Uint32(spi[:]), RemoteSPI: remoteSPI, InboundKey: initKey, OutboundKey: respKey}
	if err := s.replaceChild(replacement); err != nil {
		return nil, err
	}
	response := Proposal{Number: p.Number, Protocol: ProtoESP, SPI: spi[:], Transforms: []Transform{{Type: TransEncr, ID: encr.ID, KeyLengthBits: encr.KeyLengthBits}, {Type: TransESN, ID: ESN_NO}}}
	return s.response(ctx, msgID, CREATE_CHILD_SA, []RawPayload{{Type: PayloadSA, Body: EncodeSA([]Proposal{response})}, {Type: PayloadNonce, Body: EncodeNonce(nr)}, {Type: PayloadTSi, Body: payloads.tsi.Body}, {Type: PayloadTSr, Body: payloads.tsr.Body}})
}

func (s *Session) response(ctx *ikeContext, msgID uint32, exchange ExchangeType, inner []RawPayload) ([]byte, error) {
	flags := uint8(FlagResponse)
	if !ctx.responder {
		flags |= FlagInitiator
	}
	hdr := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: exchange, Flags: flags, MessageID: msgID}
	raw, err := ctx.encrypt(ctx.localEncryptionKey(), hdr, nil, inner)
	if err != nil {
		return nil, fmt.Errorf("ike: build response: %w", err)
	}
	return raw, nil
}

func (ctx *ikeContext) localEncryptionKey() []byte {
	if ctx.responder {
		return ctx.sker
	}
	return ctx.skei
}

func (ctx *ikeContext) peerEncryptionKey() []byte {
	if ctx.responder {
		return ctx.skei
	}
	return ctx.sker
}

func (s *Session) responseNotify(ctx *ikeContext, msgID uint32, exchange ExchangeType, notifyType NotifyType) ([]byte, error) {
	return s.responseNotifyData(ctx, msgID, exchange, notifyType, nil)
}

func (s *Session) responseNotifyData(ctx *ikeContext, msgID uint32, exchange ExchangeType, notifyType NotifyType, data []byte) ([]byte, error) {
	return s.response(ctx, msgID, exchange, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: notifyType, Data: data})}})
}
