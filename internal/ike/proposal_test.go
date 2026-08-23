package ike

import (
	"encoding/binary"
	"testing"
)

func addUnknownTVAttributeToFirstTransform(raw []byte) []byte {
	transformOffset := 8 + int(raw[6])
	transformLength := int(binary.BigEndian.Uint16(raw[transformOffset+2 : transformOffset+4]))
	insertAt := transformOffset + transformLength
	unknown := []byte{0x80, 0x0f, 0, 1}
	withAttribute := make([]byte, 0, len(raw)+len(unknown))
	withAttribute = append(withAttribute, raw[:insertAt]...)
	withAttribute = append(withAttribute, unknown...)
	withAttribute = append(withAttribute, raw[insertAt:]...)
	binary.BigEndian.PutUint16(withAttribute[2:4], uint16(len(withAttribute)))
	binary.BigEndian.PutUint16(withAttribute[transformOffset+2:transformOffset+4], uint16(transformLength+len(unknown)))
	return withAttribute
}

func TestSuiteFromProposalRequiresExactOfferSelection(t *testing.T) {
	valid := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}}
	if _, err := suiteFromProposal(valid); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []Transform{
		{Type: TransInteg, ID: 0},
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 192},
	} {
		invalid := valid
		invalid.Transforms = append(append([]Transform(nil), valid.Transforms...), extra)
		if _, err := suiteFromProposal(invalid); err == nil {
			t.Fatalf("accepted invalid selected transform %+v", extra)
		}
	}
}

func TestDecodeSARejectsInconsistentNestedFraming(t *testing.T) {
	valid := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}}}})
	for name, mutate := range map[string]func([]byte){
		"proposal marker":  func(raw []byte) { raw[0] = 1 },
		"transform marker": func(raw []byte) { raw[8] = 1 },
		"transform count":  func(raw []byte) { raw[7] = 2 },
		"trailing data":    func(raw []byte) { raw[0] = 0; raw = append(raw, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), valid...)
			if name == "trailing data" {
				raw = append(raw, 0)
			} else {
				mutate(raw)
			}
			if _, err := DecodeSA(raw); err == nil {
				t.Fatal("DecodeSA accepted inconsistent framing")
			}
		})
	}
}

func TestUnknownTransformAttributeMakesOnlyTransformUnacceptable(t *testing.T) {
	proposal := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}}
	withAttribute := addUnknownTVAttributeToFirstTransform(EncodeSA([]Proposal{proposal}))

	decoded, err := DecodeSA(withAttribute)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded[0].Transforms[0].UnsupportedAttributes {
		t.Fatal("unknown attribute was silently discarded")
	}
	selected, suite, _, ok := selectIKERekeyProposal(decoded[0], DH_CURVE25519)
	if !ok || suite.EncrKeyBits != 128 || selected[0].KeyLengthBits != 128 {
		t.Fatalf("selection did not skip attributed transform: selected=%#v suite=%#v", selected, suite)
	}

	selectedResponse := decoded[0]
	selectedResponse.Transforms = []Transform{decoded[0].Transforms[0], decoded[0].Transforms[2], decoded[0].Transforms[3]}
	if _, err := suiteFromProposal(selectedResponse); err == nil {
		t.Fatal("initiator accepted selected transform with unknown attribute")
	}
}

func TestIKERekeyProposalRejectsUnexpectedTransformType(t *testing.T) {
	proposal := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
		{Type: TransInteg, ID: 0},
	}}
	if _, _, _, ok := selectIKERekeyProposal(proposal, DH_CURVE25519); ok {
		t.Fatal("accepted IKE rekey proposal with unexpected transform type")
	}
}

func TestSupportsIdentitySignatureHash(t *testing.T) {
	identity := make([]byte, 2)
	binary.BigEndian.PutUint16(identity, HashIdentity)
	payloads := []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: identity})}}
	if ok, err := supportsSignatureHash(payloads, HashIdentity); err != nil || !ok {
		t.Fatalf("identity support = %v, %v", ok, err)
	}
	if ok, err := supportsSignatureHash(nil, HashIdentity); err != nil || ok {
		t.Fatalf("missing notification = %v, %v", ok, err)
	}
}
