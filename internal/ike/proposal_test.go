package ike

import (
	"encoding/binary"
	"testing"
)

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
