package ike

import "testing"

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
