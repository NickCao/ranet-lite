package ike

// Minimal hand-rolled DER encoder — just enough to build the RDNSequence
// identity strongSwan expects (raw-pubkey "asn1dn:#hex" identities) and the
// RFC 7427 AlgorithmIdentifier for Ed25519. Not a general ASN.1 library.

func derLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func derTLV(tag byte, content []byte) []byte {
	out := make([]byte, 0, 2+len(content))
	out = append(out, tag)
	out = append(out, derLen(len(content))...)
	out = append(out, content...)
	return out
}

func derUTF8String(s string) []byte      { return derTLV(0x0c, []byte(s)) }
func derPrintableString(s string) []byte { return derTLV(0x13, []byte(s)) }
func derSequence(parts ...[]byte) []byte { return derTLV(0x30, concat(parts...)) }
func derSet(parts ...[]byte) []byte      { return derTLV(0x31, concat(parts...)) }

func concat(parts ...[]byte) []byte {
	var n int
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// X.501 attribute type OIDs (RFC 4519), DER-encoded (tag+len+value).
var (
	oidOrganizationName = []byte{0x06, 0x03, 0x55, 0x04, 0x0a} // 2.5.4.10
	oidCommonName       = []byte{0x06, 0x03, 0x55, 0x04, 0x03} // 2.5.4.3
	oidSerialNumber     = []byte{0x06, 0x03, 0x55, 0x04, 0x05} // 2.5.4.5
)

// EncodeIdentityDN builds the DER RDNSequence ranet/strongSwan uses as a raw
// public key identity: RDNs {O=organization}, {CN=commonName},
// {serialNumber=serialNumber}, matching ranet's src/asn.rs byte for byte
// (O/CN as UTF8String, serialNumber as PrintableString).
func EncodeIdentityDN(organization, commonName, serialNumber string) []byte {
	atv := func(oid, value []byte) []byte { return derSequence(oid, value) }
	rdn := func(a []byte) []byte { return derSet(a) }
	return derSequence(
		rdn(atv(oidOrganizationName, derUTF8String(organization))),
		rdn(atv(oidCommonName, derUTF8String(commonName))),
		rdn(atv(oidSerialNumber, derPrintableString(serialNumber))),
	)
}

// Ed25519AlgorithmIdentifier is the DER SEQUENCE{OID} used both as the
// RFC 7427 signature AlgorithmIdentifier and inside a SubjectPublicKeyInfo;
// EdDSA (RFC 8410) carries no parameters.
func Ed25519AlgorithmIdentifier() []byte {
	return derSequence(OIDEd25519)
}
