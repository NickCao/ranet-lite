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

	var sa, nr, tsi, tsr *RawPayload
	for i := range response {
		switch response[i].Type {
		case PayloadN:
			n, err := DecodeNotify(response[i].Body)
			if err != nil {
				return fmt.Errorf("ike: invalid Child SA rekey notify: %w", err)
			}
			if n.Type < 16384 {
				return fmt.Errorf("ike: Child SA rekey rejected: notify type %d", n.Type)
			}
		case PayloadSA:
			sa = &response[i]
		case PayloadNonce:
			nr = &response[i]
		case PayloadTSi:
			tsi = &response[i]
		case PayloadTSr:
			tsr = &response[i]
		case PayloadKE:
			return fmt.Errorf("ike: Child SA rekey response unexpectedly includes KE")
		}
	}
	if sa == nil || nr == nil || tsi == nil || tsr == nil || len(nr.Body) == 0 {
		return fmt.Errorf("ike: incomplete Child SA rekey response")
	}
	if _, err := DecodeTS(tsi.Body); err != nil {
		return fmt.Errorf("ike: invalid Child SA rekey initiator selectors: %w", err)
	}
	if _, err := DecodeTS(tsr.Body); err != nil {
		return fmt.Errorf("ike: invalid Child SA rekey responder selectors: %w", err)
	}
	if string(tsi.Body) != string(EncodeTS([]TrafficSelector{tsv4, tsv6})) || string(tsr.Body) != string(EncodeTS([]TrafficSelector{tsv4, tsv6})) {
		return fmt.Errorf("ike: Child SA rekey response changed traffic selectors")
	}
	props, err := DecodeSA(sa.Body)
	if err != nil || len(props) != 1 || props[0].Number != 1 || props[0].Protocol != ProtoESP || len(props[0].SPI) != 4 {
		return fmt.Errorf("ike: invalid Child SA rekey proposal")
	}
	p := props[0]
	if len(p.Transforms) != 2 {
		return fmt.Errorf("ike: Child SA rekey chose unsupported transforms")
	}
	encr, ok := p.ChosenTransform(TransEncr)
	if !ok || encr.ID != old.EncrID || encr.KeyLengthBits != old.EncrKeyBits {
		return fmt.Errorf("ike: Child SA rekey chose an unsupported encryption transform")
	}
	esn, ok := p.ChosenTransform(TransESN)
	if !ok || esn.ID != ESN_NO {
		return fmt.Errorf("ike: Child SA rekey chose an unsupported ESN transform")
	}
	remoteSPI := binary.BigEndian.Uint32(p.SPI)
	if remoteSPI == 0 {
		return fmt.Errorf("ike: Child SA rekey returned zero SPI")
	}
	initKey, respKey, err := ChildSAKeymat(s.suite.PRFID, s.skD, nonce, nr.Body, encr.ID, encr.KeyLengthBits)
	if err != nil {
		return err
	}
	return s.replaceChild(ChildSA{
		EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits,
		LocalSPI: localSPI, RemoteSPI: remoteSPI,
		InboundKey: respKey, OutboundKey: initKey,
	})
}
