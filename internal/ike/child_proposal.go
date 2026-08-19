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
	if out.sa == nil || out.nonce == nil || out.tsi == nil || out.tsr == nil || len(out.nonce.Body) == 0 {
		return childExchangePayloads{}, fmt.Errorf("ike: incomplete Child SA exchange")
	}
	return out, nil
}

func canonicalEncryptionTransform(t Transform) (Transform, error) {
	if t.Type != TransEncr {
		return Transform{}, fmt.Errorf("ike: expected an encryption transform")
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
			if haveESN || transform.ID != ESN_NO || transform.KeyLengthBits != 0 {
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
		want, err := canonicalEncryptionTransform(Transform{Type: TransEncr, ID: expected.EncrID, KeyLengthBits: expected.EncrKeyBits})
		if err != nil || encryption.ID != want.ID || encryption.KeyLengthBits != want.KeyLengthBits {
			return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal changed encryption transform")
		}
	}
	return p, encryption, remoteSPI, nil
}
