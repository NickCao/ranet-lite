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

	iv := make([]byte, ap.IVLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	nonce := append(append([]byte{}, salt...), iv...)

	plain := encodePayloadChain(inner)
	plain = append(plain, 0) // zero-length padding + the pad-length octet itself

	cleartextBytes := encodePayloadChain(cleartext)

	innerFirst := PayloadNone
	if len(inner) > 0 {
		innerFirst = inner[0].Type
	}
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
	sk := m.find(PayloadSK)
	if sk == nil {
		return nil, fmt.Errorf("ike: message has no SK payload")
	}
	ap, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		return nil, err
	}
	if len(key) != ap.KeyLen+ap.SaltLen {
		return nil, fmt.Errorf("ike: key length %d does not match suite (want %d)", len(key), ap.KeyLen+ap.SaltLen)
	}
	if len(sk.Body) < ap.IVLen+ap.ICVLen {
		return nil, fmt.Errorf("ike: SK payload too short")
	}
	aead, err := newAEAD(suite.EncrID, key[:ap.KeyLen])
	if err != nil {
		return nil, err
	}
	salt := key[ap.KeyLen:]
	iv := sk.Body[:ap.IVLen]
	ciphertext := sk.Body[ap.IVLen:]
	nonce := append(append([]byte{}, salt...), iv...)

	aad := raw[:m.skHeaderOffset+genericPayloadHeaderLen]
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("ike: SK payload authentication failed: %w", err)
	}
	if len(plain) == 0 {
		return nil, fmt.Errorf("ike: empty SK plaintext")
	}
	padLen := int(plain[len(plain)-1])
	if padLen+1 > len(plain) {
		return nil, fmt.Errorf("ike: invalid SK padding")
	}
	inner := plain[:len(plain)-1-padLen]

	// Next Payload of the SK's generic header (captured at decode time)
	// tells us the type of the first inner payload.
	skGenericHeader := raw[m.skHeaderOffset : m.skHeaderOffset+genericPayloadHeaderLen]
	innerFirst := PayloadType(skGenericHeader[0])
	return decodePayloadChain(innerFirst, inner)
}
