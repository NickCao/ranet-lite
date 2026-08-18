// Package esp implements userspace ESP (RFC 4303) tunnel-mode AEAD
// encapsulation/decapsulation for exactly the Child SA negotiated by
// package ike: AES-GCM or ChaCha20-Poly1305, no ESN, one SA per direction,
// no rekey. Packets are carried UDP-encapsulated (RFC 3948) since ranet's
// strongSwan deployments force that unconditionally; see
// internal/transport.Mux for the shared socket.
package esp

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/NickCao/ranet-lite/internal/ike"
)

const (
	NextHeaderIPv4 = 4
	NextHeaderIPv6 = 41

	headerLen = 8 // SPI + 32-bit Sequence Number
)

// OutboundSA encrypts packets for the direction this client originates.
// Seal is called concurrently by design — babel's Hello/IHU timer and its
// Update timer run as independent goroutines, and both send through the
// same peer's OutboundSA — so seq/IV assignment and the actual socket
// write must be serialized under mu, or two packets can race onto the
// wire out of sequence-number order (observed in practice) or, worse,
// collide on the same seq/IV, which for AES-GCM breaks confidentiality
// and authentication outright.
type OutboundSA struct {
	aead   cipher.AEAD
	params ike.ESPAEADParams
	salt   []byte
	spi    uint32

	mu  sync.Mutex
	seq uint64 // next sequence number to use; 0 is never sent (RFC 4303 §2.2)
}

// InboundSA decrypts packets sent to this client's SPI.
type InboundSA struct {
	aead   cipher.AEAD
	params ike.ESPAEADParams
	salt   []byte
	spi    uint32
	window replayWindow
}

func NewOutbound(child ike.ChildSA) (*OutboundSA, error) {
	aead, params, err := ike.NewESPAEAD(child.EncrID, child.EncrKeyBits, child.OutboundKey)
	if err != nil {
		return nil, err
	}
	return &OutboundSA{
		aead: aead, params: params,
		salt: ike.ESPSalt(params, child.OutboundKey),
		spi:  child.RemoteSPI,
	}, nil
}

func NewInbound(child ike.ChildSA) (*InboundSA, error) {
	aead, params, err := ike.NewESPAEAD(child.EncrID, child.EncrKeyBits, child.InboundKey)
	if err != nil {
		return nil, err
	}
	return &InboundSA{
		aead: aead, params: params,
		salt: ike.ESPSalt(params, child.InboundKey),
		spi:  child.LocalSPI,
	}, nil
}

// Seal wraps one tunnel-mode IP packet (nextHeader identifies its version,
// NextHeaderIPv4/IPv6) into a full ESP packet ready for UDP encapsulation.
// The only part of this that needs to be serialized is sequence/IV
// allocation (see nextSeq) — the padding and AEAD work below touch no
// shared state, so concurrent callers each encrypt in parallel once
// they've been handed a unique seq. Go's AEAD implementations (AES-GCM,
// ChaCha20-Poly1305) are safe for concurrent Seal calls on the same
// instance as long as each call uses a distinct nonce, which nextSeq
// guarantees.
func (o *OutboundSA) Seal(innerIPPacket []byte, nextHeader byte) ([]byte, error) {
	seq, err := o.nextSeq()
	if err != nil {
		return nil, err
	}

	trailerLen := 2 // pad length + next header octets
	total := len(innerIPPacket) + trailerLen
	padLen := (4 - total%4) % 4

	plain := make([]byte, 0, len(innerIPPacket)+padLen+trailerLen)
	plain = append(plain, innerIPPacket...)
	for i := 1; i <= padLen; i++ {
		plain = append(plain, byte(i))
	}
	plain = append(plain, byte(padLen), nextHeader)

	out := make([]byte, headerLen+o.params.IVLen)
	binary.BigEndian.PutUint32(out[0:4], o.spi)
	binary.BigEndian.PutUint32(out[4:8], uint32(seq))
	binary.BigEndian.PutUint64(out[8:8+o.params.IVLen], seq) // unique per packet, monotonic

	nonce := append(append([]byte{}, o.salt...), out[headerLen:headerLen+o.params.IVLen]...)
	aad := out[:headerLen]
	ciphertext := o.aead.Seal(nil, nonce, plain, aad)
	return append(out, ciphertext...), nil
}

// nextSeq atomically allocates the next sequence number, the only state
// Seal needs to serialize.
func (o *OutboundSA) nextSeq() (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seq++
	if o.seq > 0xffffffff {
		// No ESN, no rekey in this minimal client: once the 32-bit sequence
		// space is exhausted the SA is unusable and must be re-established.
		return 0, fmt.Errorf("esp: sequence number space exhausted, SA must be re-established")
	}
	return o.seq, nil
}

// Open validates and decrypts one ESP packet addressed to this SA's SPI,
// returning the encapsulated tunnel-mode IP packet and its protocol
// (NextHeaderIPv4/IPv6).
func (in *InboundSA) Open(pkt []byte) ([]byte, byte, error) {
	if len(pkt) < headerLen+in.params.IVLen+in.params.ICVLen {
		return nil, 0, fmt.Errorf("esp: packet too short")
	}
	spi := binary.BigEndian.Uint32(pkt[0:4])
	if spi != in.spi {
		return nil, 0, fmt.Errorf("esp: SPI mismatch (got %08x, want %08x)", spi, in.spi)
	}
	seq := binary.BigEndian.Uint32(pkt[4:8])
	if err := in.window.check(seq); err != nil {
		return nil, 0, err
	}

	iv := pkt[headerLen : headerLen+in.params.IVLen]
	ciphertext := pkt[headerLen+in.params.IVLen:]
	nonce := append(append([]byte{}, in.salt...), iv...)
	aad := pkt[:headerLen]

	plain, err := in.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, 0, fmt.Errorf("esp: authentication failed: %w", err)
	}
	if len(plain) < 2 {
		return nil, 0, fmt.Errorf("esp: plaintext too short")
	}
	padLen := int(plain[len(plain)-2])
	nextHeader := plain[len(plain)-1]
	if padLen+2 > len(plain) {
		return nil, 0, fmt.Errorf("esp: invalid padding")
	}
	in.window.commit(seq)
	return plain[:len(plain)-2-padLen], nextHeader, nil
}
