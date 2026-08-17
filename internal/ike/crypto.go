package ike

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// --- Diffie-Hellman ---

// DHKeyPair wraps a crypto/ecdh key pair for one of the modern groups we
// support: Curve25519 (31, preferred) or NIST P-256/P-384 (19/20) as a
// fallback if a responder's default proposal doesn't include group 31.
type DHKeyPair struct {
	Group uint16
	curve ecdh.Curve
	priv  *ecdh.PrivateKey
}

func curveForGroup(group uint16) (ecdh.Curve, error) {
	switch group {
	case DH_CURVE25519:
		return ecdh.X25519(), nil
	case DH_ECP_256:
		return ecdh.P256(), nil
	case DH_ECP_384:
		return ecdh.P384(), nil
	default:
		return nil, fmt.Errorf("ike: unsupported DH group %d", group)
	}
}

func GenerateDH(group uint16) (*DHKeyPair, error) {
	c, err := curveForGroup(group)
	if err != nil {
		return nil, err
	}
	priv, err := c.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DHKeyPair{Group: group, curve: c, priv: priv}, nil
}

// PublicBytes returns the KE payload public value: raw u-coordinate for
// X25519, or bare X||Y (no SEC1 0x04 prefix) for the NIST curves, per
// RFC 5903 §7.
func (kp *DHKeyPair) PublicBytes() []byte {
	b := kp.priv.PublicKey().Bytes()
	if kp.Group == DH_CURVE25519 {
		return b
	}
	return b[1:] // strip the uncompressed-point format byte
}

// SharedSecret computes g^ir from the peer's KE payload public value.
func (kp *DHKeyPair) SharedSecret(peerPublic []byte) ([]byte, error) {
	raw := peerPublic
	if kp.Group != DH_CURVE25519 {
		raw = append([]byte{0x04}, peerPublic...) // restore SEC1 prefix
	}
	pub, err := kp.curve.NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("ike: invalid peer public key: %w", err)
	}
	return kp.priv.ECDH(pub)
}

// --- PRF / PRF+ , RFC 7296 §2.13 ---

func prfHashFunc(prfID uint16) (func() hash.Hash, error) {
	switch prfID {
	case PRF_HMAC_SHA2_256:
		return sha256.New, nil
	case PRF_HMAC_SHA2_384:
		return sha512.New384, nil
	default:
		return nil, fmt.Errorf("ike: unsupported PRF %d", prfID)
	}
}

// PRFOutputLen returns the natural output size of the PRF, used as SK_d and
// SK_pi/SK_pr length per RFC 5282 (AEAD ciphers derive no integrity keys).
func PRFOutputLen(prfID uint16) int {
	switch prfID {
	case PRF_HMAC_SHA2_256:
		return 32
	case PRF_HMAC_SHA2_384:
		return 48
	}
	return 0
}

func prf(prfID uint16, key, data []byte) []byte {
	hf, err := prfHashFunc(prfID)
	if err != nil {
		panic(err) // caller always validates prfID before reaching here
	}
	m := hmac.New(hf, key)
	m.Write(data)
	return m.Sum(nil)
}

// prfPlus implements prf+(K,S), RFC 7296 §2.13.
func prfPlus(prfID uint16, key, seed []byte, length int) []byte {
	var out, t []byte
	for counter := byte(1); len(out) < length; counter++ {
		in := make([]byte, 0, len(t)+len(seed)+1)
		in = append(in, t...)
		in = append(in, seed...)
		in = append(in, counter)
		t = prf(prfID, key, in)
		out = append(out, t...)
	}
	return out[:length]
}

// --- AEAD suite parameters, RFC 5282 / RFC 7634 ---

type AEADParams struct {
	KeyLen  int // encryption key length, bytes (excludes salt)
	SaltLen int
	IVLen   int // explicit per-packet IV carried on the wire
	ICVLen  int
}

func aeadParams(encrID uint16, keyLenBits uint16) (AEADParams, error) {
	switch encrID {
	case ENCR_AES_GCM_16:
		kl := int(keyLenBits) / 8
		if kl != 16 && kl != 24 && kl != 32 {
			return AEADParams{}, fmt.Errorf("ike: invalid AES-GCM key length %d bits", keyLenBits)
		}
		return AEADParams{KeyLen: kl, SaltLen: 4, IVLen: 8, ICVLen: 16}, nil
	case ENCR_CHACHA20_POLY1305:
		return AEADParams{KeyLen: 32, SaltLen: 4, IVLen: 8, ICVLen: 16}, nil
	default:
		return AEADParams{}, fmt.Errorf("ike: unsupported encryption transform %d", encrID)
	}
}

// ESPAEADParams exposes the wire-format parameters (salt/IV/ICV lengths) an
// ESP AEAD transform needs, so package esp doesn't duplicate the transform
// table already negotiated here.
type ESPAEADParams struct {
	KeyLen  int
	SaltLen int
	IVLen   int
	ICVLen  int
}

// NewESPAEAD builds an AEAD cipher for ESP packet processing from Child SA
// keying material (key||salt, as produced by ChildSAKeymat) and returns the
// wire-format parameters needed to frame packets.
func NewESPAEAD(encrID uint16, encrKeyBits uint16, keyAndSalt []byte) (cipher.AEAD, ESPAEADParams, error) {
	ap, err := aeadParams(encrID, encrKeyBits)
	if err != nil {
		return nil, ESPAEADParams{}, err
	}
	if len(keyAndSalt) != ap.KeyLen+ap.SaltLen {
		return nil, ESPAEADParams{}, fmt.Errorf("ike: key length %d does not match suite (want %d)", len(keyAndSalt), ap.KeyLen+ap.SaltLen)
	}
	aead, err := newAEAD(encrID, keyAndSalt[:ap.KeyLen])
	if err != nil {
		return nil, ESPAEADParams{}, err
	}
	return aead, ESPAEADParams{KeyLen: ap.KeyLen, SaltLen: ap.SaltLen, IVLen: ap.IVLen, ICVLen: ap.ICVLen}, nil
}

// ESPSalt returns the salt portion of key||salt keying material.
func ESPSalt(p ESPAEADParams, keyAndSalt []byte) []byte {
	return keyAndSalt[p.KeyLen:]
}

func newAEAD(encrID uint16, key []byte) (cipher.AEAD, error) {
	switch encrID {
	case ENCR_AES_GCM_16:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case ENCR_CHACHA20_POLY1305:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("ike: unsupported encryption transform %d", encrID)
	}
}

// --- IKE SA key derivation, RFC 7296 §2.14, RFC 5282 §2 (AEAD variant) ---

type SASuite struct {
	EncrID        uint16
	EncrKeyBits   uint16
	PRFID         uint16
	DHGroup       uint16
}

type IKEKeys struct {
	Suite    SASuite
	SKd      []byte
	SKei     []byte // initiator's encryption key || salt
	SKer     []byte // responder's encryption key || salt
	SKpi     []byte
	SKpr     []byte
}

// DeriveIKEKeys computes SKEYSEED and the SK_* keys for the IKE SA.
func DeriveIKEKeys(suite SASuite, sharedSecret, ni, nr []byte, spiI, spiR uint64) (*IKEKeys, error) {
	ap, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		return nil, err
	}
	prfLen := PRFOutputLen(suite.PRFID)
	if prfLen == 0 {
		return nil, fmt.Errorf("ike: unsupported PRF %d", suite.PRFID)
	}
	skeyseed := prf(suite.PRFID, append(append([]byte{}, ni...), nr...), sharedSecret)

	var spiBuf [16]byte
	putUint64(spiBuf[0:8], spiI)
	putUint64(spiBuf[8:16], spiR)
	seed := concat(ni, nr, spiBuf[:])

	skLen := ap.KeyLen + ap.SaltLen
	total := prfLen /*SK_d*/ + 2*skLen /*SK_ei,SK_er*/ + 2*prfLen /*SK_pi,SK_pr*/
	stream := prfPlus(suite.PRFID, skeyseed, seed, total)

	off := 0
	take := func(n int) []byte { b := stream[off : off+n]; off += n; return b }
	return &IKEKeys{
		Suite: suite,
		SKd:   take(prfLen),
		SKei:  take(skLen),
		SKer:  take(skLen),
		SKpi:  take(prfLen),
		SKpr:  take(prfLen),
	}, nil
}

func putUint64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

// ChildSAKeymat expands SK_d into the ESP keying material for a Child SA
// with no PFS: KEYMAT = prf+(SK_d, Ni | Nr), RFC 7296 §2.17. The returned
// slice holds, in order, the initiator's key||salt then the responder's.
func ChildSAKeymat(prfID uint16, skD, ni, nr []byte, encrID uint16, encrKeyBits uint16) (initiatorKey, responderKey []byte, err error) {
	ap, err := aeadParams(encrID, encrKeyBits)
	if err != nil {
		return nil, nil, err
	}
	each := ap.KeyLen + ap.SaltLen
	stream := prfPlus(prfID, skD, concat(ni, nr), 2*each)
	return stream[:each], stream[each:], nil
}
