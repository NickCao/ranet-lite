package ike

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// RekeyChild replaces the current Child SA without a new Diffie-Hellman
// exchange. Run must be active to service the serialized IKE request.
//
// The old Child SA is intentionally retained: retiring it requires a correct
// INFORMATIONAL Delete exchange and an ESP overlap policy.
func (s *Session) RekeyChild() error {
	return s.rekeyChild(false)
}

// RekeyChildProactively starts a packet-count-triggered Child-SA rekey. If a
// Child-SA rekey is already running, that exchange already satisfies the
// request and this method succeeds without starting a duplicate.
func (s *Session) RekeyChildProactively() error {
	return s.rekeyChild(true)
}

func (s *Session) rekeyChild(alreadyRunningIsSuccess bool) error {
	if !s.childRekeying.CompareAndSwap(false, true) {
		if alreadyRunningIsSuccess {
			return nil
		}
		return fmt.Errorf("ike: Child SA rekey already in progress")
	}
	defer s.childRekeying.Store(false)
	old := s.currentChild()
	if old.LocalSPI == 0 && old.RemoteSPI == 0 {
		return s.negotiateChild(nil)
	}
	if old.LocalSPI == 0 || old.RemoteSPI == 0 {
		return fmt.Errorf("ike: no Child SA to rekey")
	}
	err := s.negotiateChild(&old)
	var rejected *childNegotiationRejectedError
	if !errors.As(err, &rejected) || rejected.notify.Type != N_CHILD_SA_NOT_FOUND {
		return err
	}
	if rejected.notify.Protocol != ProtoESP || len(rejected.notify.SPI) != 4 || binary.BigEndian.Uint32(rejected.notify.SPI) != old.LocalSPI {
		return fmt.Errorf("ike: invalid CHILD_SA_NOT_FOUND response")
	}
	// The peer no longer has this SA, so no Delete exchange is possible.
	// RFC 7296 §2.25 recommends silently removing our stale half and creating
	// a new Child SA from scratch.
	if err := s.forgetChild(old); err != nil {
		return fmt.Errorf("ike: forget missing peer Child SA: %w", err)
	}
	return s.negotiateChild(nil)
}

func (s *Session) negotiateChild(old *ChildSA) error {
	localSPI := randUint32Nonzero()
	for old != nil && localSPI == old.LocalSPI {
		localSPI = randUint32Nonzero()
	}
	spi := make([]byte, 4)
	binary.BigEndian.PutUint32(spi, localSPI)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("ike: generate Child SA rekey nonce: %w", err)
	}
	tsv4, tsv6 := FullRangeV4(), FullRangeV6()
	inner := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal(spi)})},
		{Type: PayloadNonce, Body: EncodeNonce(nonce)},
		{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
		{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
	}
	var oldLocalSPI []byte
	if old != nil {
		oldLocalSPI = make([]byte, 4)
		binary.BigEndian.PutUint32(oldLocalSPI, old.LocalSPI)
		// REKEY_SA identifies the old SA by the SPI this exchange's
		// initiator expects in inbound ESP packets (RFC 7296 §1.3.3).
		inner = append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Protocol: ProtoESP, SPI: oldLocalSPI, Type: N_REKEY_SA})}}, inner...)
	}
	response, err := s.request(CREATE_CHILD_SA, inner)
	if err != nil {
		return fmt.Errorf("ike: Child SA negotiation request: %w", err)
	}

	payloads, err := decodeChildNegotiationResponse(response)
	if err != nil {
		return err
	}
	if err := validateFullRangeSelectors(payloads.tsi, payloads.tsr); err != nil {
		return err
	}
	_, encr, remoteSPI, err := decodeChildProposal(payloads.sa.Body, old)
	if err != nil {
		return fmt.Errorf("ike: invalid Child SA response proposal: %w", err)
	}
	context := s.currentContext()
	initKey, respKey, err := ChildSAKeymat(context.suite.PRFID, context.skD, nonce, payloads.nonce.Body, encr.ID, encr.KeyLengthBits)
	if err != nil {
		return err
	}
	if err := s.replaceChild(ChildSA{
		EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits,
		LocalSPI: localSPI, RemoteSPI: remoteSPI,
		InboundKey: respKey, OutboundKey: initKey,
	}); err != nil {
		return err
	}
	if old == nil {
		return nil
	}
	deleted, err := s.request(INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{oldLocalSPI}})}})
	if err != nil {
		return fmt.Errorf("ike: retire replaced Child SA: %w", err)
	}
	for _, p := range deleted {
		if p.Type != PayloadD {
			continue
		}
		d, err := DecodeDelete(p.Body)
		if err != nil {
			return fmt.Errorf("ike: invalid Child SA retire response: %w", err)
		}
		for _, spi := range d.SPIs {
			if d.Protocol == ProtoESP && len(spi) == 4 && binary.BigEndian.Uint32(spi) == old.RemoteSPI {
				return s.retireChild(old.RemoteSPI)
			}
		}
	}
	return fmt.Errorf("ike: Child SA retire response did not delete peer inbound SPI")
}

type childNegotiationRejectedError struct{ notify Notify }

func (e *childNegotiationRejectedError) Error() string {
	return fmt.Sprintf("ike: Child SA negotiation rejected: notify type %d", e.notify.Type)
}

func decodeChildNegotiationResponse(response []RawPayload) (childExchangePayloads, error) {
	payloads, err := parseChildExchangePayloads(response)
	if err != nil {
		return childExchangePayloads{}, fmt.Errorf("ike: invalid Child SA negotiation response: %w", err)
	}
	// An error response can consist solely of a Notify payload. Interpret the
	// authenticated error before requiring the SA, Nr, TSi, and TSr payloads
	// that RFC 7296 §§1.3.1 and 1.3.3 specify for a successful response.
	for _, notify := range payloads.notifies {
		if notify.Type < 16384 {
			return childExchangePayloads{}, &childNegotiationRejectedError{notify: notify}
		}
	}
	if err := validateCompleteChildExchange(payloads); err != nil {
		return childExchangePayloads{}, fmt.Errorf("ike: invalid Child SA negotiation response: %w", err)
	}
	return payloads, nil
}
