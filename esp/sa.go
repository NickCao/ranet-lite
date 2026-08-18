package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChildSA contains the ESP parameters and directional key material negotiated
// by an IKEv2 implementation. Keys include their four-byte AEAD salt.
type ChildSA struct {
	EncrID      uint16
	EncrKeyBits uint16
	LocalSPI    uint32
	RemoteSPI   uint32
	InboundKey  []byte
	OutboundKey []byte
}

const (
	ENCRAESGCM16         uint16 = 20
	ENCRChaCha20Poly1305 uint16 = 28
)

type aeadParams struct {
	keyLen, saltLen, IVLen, ICVLen int
}

func newESPAEAD(id, bits uint16, key []byte) (cipher.AEAD, aeadParams, error) {
	p := aeadParams{saltLen: 4, IVLen: 8, ICVLen: 16}
	switch id {
	case ENCRAESGCM16:
		p.keyLen = int(bits) / 8
		if p.keyLen != 16 && p.keyLen != 24 && p.keyLen != 32 {
			return nil, aeadParams{}, fmt.Errorf("esp: invalid AES-GCM key length %d bits", bits)
		}
		if len(key) != p.keyLen+p.saltLen {
			return nil, aeadParams{}, fmt.Errorf("esp: key length %d does not match suite", len(key))
		}
		block, err := aes.NewCipher(key[:p.keyLen])
		if err != nil {
			return nil, aeadParams{}, err
		}
		aead, err := cipher.NewGCM(block)
		return aead, p, err
	case ENCRChaCha20Poly1305:
		p.keyLen = 32
		if bits != 0 && bits != 256 {
			return nil, aeadParams{}, fmt.Errorf("esp: invalid ChaCha20-Poly1305 key length %d bits", bits)
		}
		if len(key) != p.keyLen+p.saltLen {
			return nil, aeadParams{}, fmt.Errorf("esp: key length %d does not match suite", len(key))
		}
		aead, err := chacha20poly1305.New(key[:p.keyLen])
		return aead, p, err
	default:
		return nil, aeadParams{}, fmt.Errorf("esp: unsupported encryption transform %d", id)
	}
}
