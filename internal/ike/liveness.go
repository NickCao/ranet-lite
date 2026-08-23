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
		raw, source, err := s.mux.RecvIKEFromUntil(deadline)
		if err != nil {
			if !transport.IsTimeout(err) {
				if pending != nil {
					pending.result <- requestResult{err: err}
				}
				return err
			}
			if pending != nil && !time.Now().Before(pending.deadline) {
				if pendingRetransmitsExhausted(pending) {
					s.mux.Close()
					return fmt.Errorf("ike: DPD failed: no response after %d attempts", maxRetransmits)
				}
				// RFC 7296 §2.1 requires retaining and retransmitting the
				// bitwise-identical request until a response arrives or the IKE SA
				// is declared failed. Ordinary exchanges keep retrying at the
				// capped interval; only DPD applies the finite failure policy.
				if err := s.sendPending(pending); err != nil {
					if pending.dpd {
						s.mux.Close()
						return fmt.Errorf("ike: DPD failed: %w", err)
					}
					slog.Warn("ike request retransmission failed; retrying", "exchange", pending.exchange, "message_id", pending.msgID, "err", err)
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
		if s.dispatch(raw, source, &pending) {
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
	// A failed first send did not put a request on the wire, so it must not
	// consume a Message ID. Once sent, this exact request owns the ID until its
	// response arrives (RFC 7296 §2.1-§2.2).
	context.nextLocalMID++
	return pending, nil
}

func (s *Session) sendPending(pending *pendingRequest) error {
	nextAttempt := min(pending.attempts+1, maxRetransmits)
	pending.deadline = time.Now().Add(retransmitDelay(nextAttempt))
	if err := s.mux.SendIKE(pending.raw); err != nil {
		return err
	}
	pending.attempts = nextAttempt
	return nil
}

func pendingRetransmitsExhausted(pending *pendingRequest) bool {
	return pending.dpd && pending.attempts >= maxRetransmits
}

func retransmitDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return requestTimeout
	}
	return requestTimeout << min(attempt-1, maxRetransmits-1)
}

// dispatch returns true only when raw is a fresh authenticated message. Run
// uses that result as evidence of peer liveness; authenticated replays may
// receive a cached response, but must not refresh DPD or migrate the endpoint.
func (s *Session) dispatch(raw []byte, source transport.Endpoint, pending **pendingRequest) bool {
	hdr, err := decodeHeader(raw)
	if err != nil {
		return false
	}
	if hdr.MajorVersion != 2 || hdr.Length != uint32(len(raw)) {
		return false
	}
	ctx := s.contextForHeader(hdr)
	if ctx == nil {
		return false
	}
	var matching *pendingRequest
	if hdr.IsResponse() {
		matching = *pending
		if hdr.IsInitiator() != ctx.responder || matching == nil || matching.context != ctx ||
			hdr.MessageID != matching.msgID || hdr.ExchangeType != matching.exchange {
			return false
		}
	} else if hdr.IsInitiator() != ctx.responder {
		return false
	}
	outer, err := DecodeMessage(raw)
	if err != nil {
		return false
	}
	innerFirst, plaintext, err := decryptMessagePlaintext(ctx.suite, ctx.peerEncryptionKey(), raw, outer)
	if err != nil {
		return false
	}
	if matching == nil {
		s.stateMu.RLock()
		nextPeerMID := ctx.nextPeerMID
		lastPeerResponseID := ctx.lastPeerResponseID
		lastPeerResponse := ctx.lastPeerResponse
		s.stateMu.RUnlock()
		if hdr.MessageID != nextPeerMID {
			if nextPeerMID > 0 && hdr.MessageID == nextPeerMID-1 && lastPeerResponseID == hdr.MessageID {
				if err := s.mux.SendIKETo(lastPeerResponse, source); err != nil {
					s.mux.Close()
				}
			}
			return false
		}
		// Authentication and a fresh Message ID prove this request came from
		// the live peer rather than being a replay. Only now may it update the
		// endpoint used for future IKE and ESP traffic after NAT port rebinding
		// (RFC 7296 §2.4 and §2.23).
		s.mux.AdoptEndpoint(source)
	}
	inner, err := decodeMessagePlaintext(innerFirst, plaintext)
	if err != nil {
		if matching != nil {
			matching.result <- requestResult{err: fmt.Errorf("ike: malformed authenticated response: %w", err)}
			*pending = nil
		} else if response, responseErr := s.responseNotify(ctx, hdr.MessageID, hdr.ExchangeType, N_INVALID_SYNTAX); responseErr == nil {
			_ = s.mux.SendIKETo(response, source)
		}
		// RFC 7296 §2.21.3 makes authenticated INVALID_SYNTAX fatal to the
		// IKE SA. Responses never generate a further error response.
		s.mux.Close()
		return true
	}
	if matching != nil {
		matching.result <- requestResult{inner: inner}
		*pending = nil
		return true
	}
	response, err := s.handleRequest(ctx, hdr, inner)
	if err != nil {
		if response != nil {
			_ = s.mux.SendIKETo(response, source)
		}
		s.mux.Close()
		return true
	}
	s.stateMu.Lock()
	ctx.lastPeerResponseID = hdr.MessageID
	ctx.lastPeerResponse = response
	ctx.nextPeerMID++
	s.stateMu.Unlock()
	if err := s.mux.SendIKETo(response, source); err != nil {
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
		var deletes []Delete
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
			deletes = append(deletes, d)
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
		}
		var responseSPIs [][]byte
		for _, d := range deletes {
			if d.Protocol != ProtoESP {
				continue
			}
			remoteSPIs := make([]uint32, len(d.SPIs))
			for i, spi := range d.SPIs {
				remoteSPIs[i] = binary.BigEndian.Uint32(spi)
			}
			localSPIs, err := s.deleteChildren(remoteSPIs)
			if err != nil {
				return nil, err
			}
			for _, localSPI := range localSPIs {
				spi := make([]byte, 4)
				binary.BigEndian.PutUint32(spi, localSPI)
				responseSPIs = append(responseSPIs, spi)
			}
		}
		var responsePayloads []RawPayload
		if len(responseSPIs) > 0 {
			responsePayloads = []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: responseSPIs})}}
		}
		return s.response(ctx, hdr.MessageID, INFORMATIONAL, responsePayloads)
	}
	if hdr.ExchangeType == CREATE_CHILD_SA {
		if sa := findType(inner, PayloadSA); sa != nil {
			props, err := DecodeSA(sa.Body)
			if err == nil && len(props) > 0 && props[0].Protocol == ProtoIKE {
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
	var rekey Notify
	for _, payload := range inner {
		if payload.Type != PayloadN {
			continue
		}
		notify, err := DecodeNotify(payload.Body)
		if err != nil {
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
		}
		if notify.Type == N_REKEY_SA {
			rekey = notify
		}
	}
	// A CREATE_CHILD_SA request without REKEY_SA asks to create an additional
	// Child SA. This single-Child-SA implementation rejects it with the error
	// required by RFC 7815 §2.2 and described by RFC 7296 §1.3.
	if rekey.Type != N_REKEY_SA {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_ADDITIONAL_SAS)
	}
	if s.childRekeying.Load() {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	if rekey.Protocol != ProtoESP || len(rekey.SPI) != 4 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	payloads, err := decodeChildExchangePayloads(inner)
	if err != nil {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	child := s.currentChild()
	if binary.BigEndian.Uint32(rekey.SPI) != child.RemoteSPI {
		// RFC 7296 §2.25 requires CHILD_SA_NOT_FOUND to identify the
		// nonexistent SA by copying the Protocol ID and SPI from REKEY_SA.
		return s.responseNotifySA(ctx, msgID, CREATE_CHILD_SA, N_CHILD_SA_NOT_FOUND, rekey.Protocol, rekey.SPI)
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

func (s *Session) responseNotifySA(ctx *ikeContext, msgID uint32, exchange ExchangeType, notifyType NotifyType, protocol ProtocolID, spi []byte) ([]byte, error) {
	return s.response(ctx, msgID, exchange, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Protocol: protocol, SPI: spi, Type: notifyType})}})
}
