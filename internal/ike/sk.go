package ike

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// EncryptMessage builds a full IKEv2 message wire image whose payloads
// (after any cleartext ones, of which our profile has none post-IKE_SA_INIT)
// are carried inside a single SK payload, per RFC 7296 §3.14 / RFC 5282.
//
// key is SK_ei or SK_er (encryption key || salt) depending on direction.
func EncryptMessage(suite SASuite, key []byte, hdr Header, cleartext, inner []RawPayload) ([]byte, error) {
	var iv [8]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return nil, err
	}
	return encryptMessageIV(suite, key, hdr, cleartext, inner, iv[:])
}

func (c *ikeContext) encrypt(key []byte, hdr Header, cleartext, inner []RawPayload) ([]byte, error) {
	value := c.sendIV.Add(1)
	if value == 0 {
		return nil, fmt.Errorf("ike: AEAD IV space exhausted")
	}
	var iv [8]byte
	binary.BigEndian.PutUint64(iv[:], value)
	return encryptMessageIV(c.suite, key, hdr, cleartext, inner, iv[:])
}

func encryptMessageIV(suite SASuite, key []byte, hdr Header, cleartext, inner []RawPayload, iv []byte) ([]byte, error) {
	plain := encodePayloadChain(inner)
	plain = append(plain, 0) // zero-length padding + the pad-length octet itself
	innerFirst := PayloadNone
	if len(inner) > 0 {
		innerFirst = inner[0].Type
	}
	return encryptMessagePlaintextIV(suite, key, hdr, cleartext, innerFirst, plain, iv)
}

func encryptMessagePlaintextIV(suite SASuite, key []byte, hdr Header, cleartext []RawPayload, innerFirst PayloadType, plain, iv []byte) ([]byte, error) {
	ap, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		return nil, err
	}
	if len(key) != ap.KeyLen+ap.SaltLen {
		return nil, fmt.Errorf("ike: key length %d does not match suite (want %d)", len(key), ap.KeyLen+ap.SaltLen)
	}
	aead, err := newAEAD(suite.EncrID, key[:ap.KeyLen])
	if err != nil {
		return nil, err
	}
	salt := key[ap.KeyLen:]

	if len(iv) != ap.IVLen {
		return nil, fmt.Errorf("ike: IV length %d does not match suite", len(iv))
	}
	nonce := append(append([]byte{}, salt...), iv...)

	cleartextBytes := encodePayloadChain(cleartext)

	skHdr := make([]byte, genericPayloadHeaderLen)
	skHdr[0] = byte(innerFirst)
	ciphertextLen := len(plain) + ap.ICVLen
	binary.BigEndian.PutUint16(skHdr[2:4], uint16(genericPayloadHeaderLen+ap.IVLen+ciphertextLen))

	firstOuter := PayloadSK
	if len(cleartext) > 0 {
		firstOuter = cleartext[0].Type
	}
	h := hdr
	h.NextPayload = firstOuter
	h.Length = uint32(HeaderLen + len(cleartextBytes) + len(skHdr) + ap.IVLen + ciphertextLen)
	headerBytes := h.encode()

	aad := concat(headerBytes, cleartextBytes, skHdr)
	ciphertext := aead.Seal(nil, nonce, plain, aad)

	out := make([]byte, 0, int(h.Length))
	out = append(out, headerBytes...)
	out = append(out, cleartextBytes...)
	out = append(out, skHdr...)
	out = append(out, iv...)
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptMessage decrypts the SK payload of an already-decoded Message
// (from DecodeMessage) and returns the inner payloads. raw must be the
// exact bytes passed to DecodeMessage. key is SK_ei or SK_er depending on
// which side sent the message.
func DecryptMessage(suite SASuite, key []byte, raw []byte, m *Message) ([]RawPayload, error) {
	innerFirst, plain, err := decryptMessagePlaintext(suite, key, raw, m)
	if err != nil {
		return nil, err
	}
	return decodeMessagePlaintext(innerFirst, plain)
}

// decryptMessagePlaintext returns only after the SK payload's AEAD tag has
// authenticated. Keeping plaintext parsing separate lets post-handshake
// request handling distinguish unauthenticated packets from authenticated
// INVALID_SYNTAX errors as required by RFC 7296 §2.21.3.
func decryptMessagePlaintext(suite SASuite, key []byte, raw []byte, m *Message) (PayloadType, []byte, error) {
	sk := m.find(PayloadSK)
	if sk == nil {
		return PayloadNone, nil, fmt.Errorf("ike: message has no SK payload")
	}
	ap, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		return PayloadNone, nil, err
	}
	if len(key) != ap.KeyLen+ap.SaltLen {
		return PayloadNone, nil, fmt.Errorf("ike: key length %d does not match suite (want %d)", len(key), ap.KeyLen+ap.SaltLen)
	}
	if len(sk.Body) < ap.IVLen+ap.ICVLen {
		return PayloadNone, nil, fmt.Errorf("ike: SK payload too short")
	}
	aead, err := newAEAD(suite.EncrID, key[:ap.KeyLen])
	if err != nil {
		return PayloadNone, nil, err
	}
	salt := key[ap.KeyLen:]
	iv := sk.Body[:ap.IVLen]
	ciphertext := sk.Body[ap.IVLen:]
	nonce := append(append([]byte{}, salt...), iv...)

	aad := raw[:m.skHeaderOffset+genericPayloadHeaderLen]
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return PayloadNone, nil, fmt.Errorf("ike: SK payload authentication failed: %w", err)
	}
	skGenericHeader := raw[m.skHeaderOffset : m.skHeaderOffset+genericPayloadHeaderLen]
	return PayloadType(skGenericHeader[0]), plain, nil
}

func decodeMessagePlaintext(innerFirst PayloadType, plain []byte) ([]RawPayload, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("ike: empty SK plaintext")
	}
	padLen := int(plain[len(plain)-1])
	if padLen+1 > len(plain) {
		return nil, fmt.Errorf("ike: invalid SK padding")
	}
	inner := plain[:len(plain)-1-padLen]

	return decodePayloadChain(innerFirst, inner)
}
