package ike

import (
	"crypto/ed25519"
	"fmt"
)

// BuildAuth constructs an RFC 7427 "Digital Signature" AUTH payload body
// signing signedOctets with an Ed25519 key, per RFC 8420 (EdDSA in IKEv2):
// PureEdDSA over the raw octets, AlgorithmIdentifier = SEQUENCE{OID 1.3.101.112}.
func BuildAuth(priv ed25519.PrivateKey, signedOctets []byte) []byte {
	algID := Ed25519AlgorithmIdentifier()
	sig := ed25519.Sign(priv, signedOctets)
	b := make([]byte, 4+1+len(algID)+len(sig))
	b[0] = AuthDigitalSignature
	b[4] = byte(len(algID))
	copy(b[5:], algID)
	copy(b[5+len(algID):], sig)
	return b
}

// VerifyAuth checks an RFC 7427 Digital Signature AUTH payload from an
// Ed25519 peer. Only Ed25519 is supported — anything else is rejected,
// since that's the only method ranet's strongSwan deployments use.
func VerifyAuth(pub ed25519.PublicKey, signedOctets, authBody []byte) error {
	if len(authBody) < 5 {
		return fmt.Errorf("ike: short AUTH payload")
	}
	if authBody[0] != AuthDigitalSignature {
		return fmt.Errorf("ike: unsupported auth method %d (want Digital Signature)", authBody[0])
	}
	algLen := int(authBody[4])
	if len(authBody) < 5+algLen {
		return fmt.Errorf("ike: truncated AUTH AlgorithmIdentifier")
	}
	algID := authBody[5 : 5+algLen]
	want := Ed25519AlgorithmIdentifier()
	if !bytesEqual(algID, want) {
		return fmt.Errorf("ike: unsupported signature algorithm in AUTH payload")
	}
	sig := authBody[5+algLen:]
	if !ed25519.Verify(pub, signedOctets, sig) {
		return fmt.Errorf("ike: AUTH signature verification failed")
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
