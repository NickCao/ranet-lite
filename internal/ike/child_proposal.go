package ike

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func fullRangeSelectors() []byte {
	return EncodeTS([]TrafficSelector{FullRangeV4(), FullRangeV6()})
}

func validateFullRangeSelectors(tsi, tsr *RawPayload) error {
	if tsi == nil || tsr == nil {
		return fmt.Errorf("ike: Child SA exchange is missing traffic selectors")
	}
	want := fullRangeSelectors()
	if _, err := DecodeTS(tsi.Body); err != nil || !bytes.Equal(tsi.Body, want) {
		return fmt.Errorf("ike: unsupported initiator traffic selectors")
	}
	if _, err := DecodeTS(tsr.Body); err != nil || !bytes.Equal(tsr.Body, want) {
		return fmt.Errorf("ike: unsupported responder traffic selectors")
	}
	return nil
}

type childExchangePayloads struct {
	sa, nonce, tsi, tsr *RawPayload
	notifies            []Notify
}

func decodeChildExchangePayloads(payloads []RawPayload) (childExchangePayloads, error) {
	out, err := parseChildExchangePayloads(payloads)
	if err != nil {
		return childExchangePayloads{}, err
	}
	if err := validateCompleteChildExchange(out); err != nil {
		return childExchangePayloads{}, err
	}
	return out, nil
}

func parseChildExchangePayloads(payloads []RawPayload) (childExchangePayloads, error) {
	var out childExchangePayloads
	setUnique := func(dst **RawPayload, payload *RawPayload) error {
		if *dst != nil {
			return fmt.Errorf("ike: duplicate payload type %d in Child SA exchange", payload.Type)
		}
		*dst = payload
		return nil
	}
	for i := range payloads {
		payload := &payloads[i]
		var err error
		switch payload.Type {
		case PayloadSA:
			err = setUnique(&out.sa, payload)
		case PayloadNonce:
			err = setUnique(&out.nonce, payload)
		case PayloadTSi:
			err = setUnique(&out.tsi, payload)
		case PayloadTSr:
			err = setUnique(&out.tsr, payload)
		case PayloadN:
			notify, decodeErr := DecodeNotify(payload.Body)
			if decodeErr != nil {
				return childExchangePayloads{}, decodeErr
			}
			out.notifies = append(out.notifies, notify)
		case PayloadKE:
			return childExchangePayloads{}, fmt.Errorf("ike: Child SA exchange unexpectedly includes KE")
		default:
			if payload.Critical {
				return childExchangePayloads{}, fmt.Errorf("ike: unsupported critical payload type %d", payload.Type)
			}
		}
		if err != nil {
			return childExchangePayloads{}, err
		}
	}
	return out, nil
}

func validateCompleteChildExchange(payloads childExchangePayloads) error {
	if payloads.sa == nil || payloads.nonce == nil || payloads.tsi == nil || payloads.tsr == nil || !validNonce(payloads.nonce.Body) {
		return fmt.Errorf("ike: incomplete Child SA exchange")
	}
	return nil
}

func validNonce(nonce []byte) bool { return len(nonce) >= 16 && len(nonce) <= 256 }

func canonicalEncryptionTransform(t Transform) (Transform, error) {
	if t.Type != TransEncr {
		return Transform{}, fmt.Errorf("ike: expected an encryption transform")
	}
	if t.UnsupportedAttributes {
		return Transform{}, fmt.Errorf("ike: encryption transform has unsupported attributes")
	}
	if t.ID == ENCR_CHACHA20_POLY1305 && t.KeyLengthBits != 0 {
		return Transform{}, fmt.Errorf("ike: ChaCha20-Poly1305 has a fixed key length")
	}
	if _, err := aeadParams(t.ID, t.KeyLengthBits); err != nil {
		return Transform{}, err
	}
	if t.ID == ENCR_CHACHA20_POLY1305 {
		t.KeyLengthBits = 256
	}
	return t, nil
}

// decodeChildProposal validates the selected, single ESP proposal shared by
// IKE_AUTH and both CREATE_CHILD_SA directions.
func decodeChildProposal(body []byte, expected *ChildSA) (Proposal, Transform, uint32, error) {
	props, err := DecodeSA(body)
	if err != nil || len(props) != 1 {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: invalid Child SA proposal")
	}
	p := props[0]
	if p.Number != 1 || p.Protocol != ProtoESP || len(p.SPI) != 4 || len(p.Transforms) != 2 {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: invalid Child SA proposal shape")
	}
	remoteSPI := binary.BigEndian.Uint32(p.SPI)
	if remoteSPI == 0 {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has a zero SPI")
	}
	var encryption Transform
	var haveEncryption, haveESN bool
	for _, transform := range p.Transforms {
		switch transform.Type {
		case TransEncr:
			if haveEncryption {
				return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has duplicate encryption transforms")
			}
			encryption, err = canonicalEncryptionTransform(transform)
			if err != nil {
				return Proposal{}, Transform{}, 0, err
			}
			haveEncryption = true
		case TransESN:
			if haveESN || transform.ID != ESN_NO || transform.KeyLengthBits != 0 || transform.UnsupportedAttributes {
				return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has an unsupported ESN transform")
			}
			haveESN = true
		default:
			return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has transform type %d", transform.Type)
		}
	}
	if !haveEncryption || !haveESN {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: incomplete Child SA proposal")
	}
	if expected != nil {
		wantBits := expected.EncrKeyBits
		if expected.EncrID == ENCR_CHACHA20_POLY1305 {
			wantBits = 0
		}
		want, err := canonicalEncryptionTransform(Transform{Type: TransEncr, ID: expected.EncrID, KeyLengthBits: wantBits})
		if err != nil || encryption.ID != want.ID || encryption.KeyLengthBits != want.KeyLengthBits {
			return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal changed encryption transform")
		}
	} else {
		matched := false
		for _, offered := range espProposal(nil).Transforms {
			if offered.Type != TransEncr {
				continue
			}
			canonical, err := canonicalEncryptionTransform(offered)
			if err == nil && canonical.ID == encryption.ID && canonical.KeyLengthBits == encryption.KeyLengthBits {
				matched = true
				break
			}
		}
		if !matched {
			return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal selected an unoffered transform")
		}
	}
	return p, encryption, remoteSPI, nil
}

// selectChildRekeyProposal selects the current Child SA's encryption suite
// from a peer's offer. RFC 7296 §3.3.6 requires skipping an unacceptable
// transform while continuing with other transforms of the same type.
func selectChildRekeyProposal(body []byte, expected ChildSA) (Proposal, Transform, uint32, error) {
	props, err := DecodeSA(body)
	if err != nil {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: invalid Child SA proposal")
	}
	wantBits := expected.EncrKeyBits
	if expected.EncrID == ENCR_CHACHA20_POLY1305 {
		wantBits = 0
	}
	want, err := canonicalEncryptionTransform(Transform{Type: TransEncr, ID: expected.EncrID, KeyLengthBits: wantBits})
	if err != nil {
		return Proposal{}, Transform{}, 0, err
	}
	for _, p := range props {
		if p.Number == 0 || p.Protocol != ProtoESP || len(p.SPI) != 4 || binary.BigEndian.Uint32(p.SPI) == 0 {
			continue
		}
		var encryption Transform
		var haveEncryption, haveESN, unacceptable bool
		for _, transform := range p.Transforms {
			switch transform.Type {
			case TransEncr:
				candidate, err := canonicalEncryptionTransform(transform)
				if err == nil && !haveEncryption && candidate.ID == want.ID && candidate.KeyLengthBits == want.KeyLengthBits {
					encryption = candidate
					haveEncryption = true
				}
			case TransESN:
				if !haveESN && transform.ID == ESN_NO && transform.KeyLengthBits == 0 && !transform.UnsupportedAttributes {
					haveESN = true
				}
			default:
				unacceptable = true
			}
		}
		if !unacceptable && haveEncryption && haveESN {
			return p, encryption, binary.BigEndian.Uint32(p.SPI), nil
		}
	}
	return Proposal{}, Transform{}, 0, fmt.Errorf("ike: no acceptable Child SA proposal")
}
