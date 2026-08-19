package ike

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// RekeyChild replaces the current Child SA without a new Diffie-Hellman
// exchange. Run must be active to service the serialized IKE request.
//
// The old Child SA is intentionally retained: retiring it requires a correct
// INFORMATIONAL Delete exchange and an ESP overlap policy.
func (s *Session) RekeyChild() error {
	if !s.childRekeying.CompareAndSwap(false, true) {
		return fmt.Errorf("ike: Child SA rekey already in progress")
	}
	defer s.childRekeying.Store(false)
	old := s.currentChild()
	if old.LocalSPI == 0 || old.RemoteSPI == 0 {
		return fmt.Errorf("ike: no Child SA to rekey")
	}
	localSPI := randUint32Nonzero()
	for localSPI == old.LocalSPI {
		localSPI = randUint32Nonzero()
	}
	spi := make([]byte, 4)
	binary.BigEndian.PutUint32(spi, localSPI)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("ike: generate Child SA rekey nonce: %w", err)
	}
	oldLocalSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(oldLocalSPI, old.LocalSPI)
	oldRemoteSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(oldRemoteSPI, old.RemoteSPI)
	tsv4, tsv6 := FullRangeV4(), FullRangeV6()
	inner := []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Protocol: ProtoESP, SPI: oldRemoteSPI, Type: N_REKEY_SA})},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal(spi)})},
		{Type: PayloadNonce, Body: EncodeNonce(nonce)},
		{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
		{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
	}
	response, err := s.request(CREATE_CHILD_SA, inner)
	if err != nil {
		return fmt.Errorf("ike: Child SA rekey request: %w", err)
	}

	payloads, err := decodeChildExchangePayloads(response)
	if err != nil {
		return fmt.Errorf("ike: invalid Child SA rekey response: %w", err)
	}
	for _, notify := range payloads.notifies {
		if notify.Type < 16384 {
			return fmt.Errorf("ike: Child SA rekey rejected: notify type %d", notify.Type)
		}
	}
	if err := validateFullRangeSelectors(payloads.tsi, payloads.tsr); err != nil {
		return err
	}
	_, encr, remoteSPI, err := decodeChildProposal(payloads.sa.Body, &old)
	if err != nil {
		return fmt.Errorf("ike: invalid Child SA rekey proposal: %w", err)
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
