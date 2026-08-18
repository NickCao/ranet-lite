// Package esp implements userspace ESP (RFC 4303) tunnel-mode AEAD
// encapsulation/decapsulation for exactly the Child SA negotiated by
// package ike: AES-GCM or ChaCha20-Poly1305, no ESN, one SA per direction.
// Peer-initiated Child SA rekeys replace these instances in the production
// data plane. Packets are carried UDP-encapsulated (RFC 3948) since ranet's
// strongSwan deployments force that unconditionally; see
// internal/transport.Mux for the shared socket.
package esp

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
)

const (
	NextHeaderIPv4 = 4
	NextHeaderIPv6 = 41

	headerLen = 8 // SPI + 32-bit Sequence Number
)

// OutboundSA encrypts packets for the direction this client originates.
// Seal is called concurrently by design — every peer's babel timers and
// the mesh's outbound dispatch (see netstack.Mesh.outboundLoop) all seal
// packets through the same OutboundSA from separate goroutines — so
// sequence/IV assignment must be atomic, or two packets can collide on
// the same seq/IV, which for AES-GCM breaks confidentiality and
// authentication outright.
type OutboundSA struct {
	aead   cipher.AEAD
	params aeadParams
	salt   []byte
	spi    uint32

	seq atomic.Uint64 // next sequence number to use; 0 is never sent (RFC 4303 §2.2)
}

// InboundSA decrypts packets sent to this client's SPI. Open supports calls
// from concurrent workers using a locked check-decrypt-recheck-commit pattern:
// the (cheap) window check
// is done once up front to reject an obviously-bad packet before paying
// for AEAD decryption, and again after decryption (still under lock,
// atomically with commit) to catch a packet that raced with a concurrent
// decrypt of the same or a newer sequence number in between.
type InboundSA struct {
	aead   cipher.AEAD
	params aeadParams
	salt   []byte
	spi    uint32

	mu     sync.Mutex
	window replayWindow
}

func NewOutbound(child ChildSA) (*OutboundSA, error) {
	aead, params, err := newESPAEAD(child.EncrID, child.EncrKeyBits, child.OutboundKey)
	if err != nil {
		return nil, err
	}
	return &OutboundSA{
		aead: aead, params: params,
		salt: child.OutboundKey[params.keyLen:],
		spi:  child.RemoteSPI,
	}, nil
}

func NewInbound(child ChildSA) (*InboundSA, error) {
	aead, params, err := newESPAEAD(child.EncrID, child.EncrKeyBits, child.InboundKey)
	if err != nil {
		return nil, err
	}
	return &InboundSA{
		aead: aead, params: params,
		salt: child.InboundKey[params.keyLen:],
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

	framingLen := headerLen + o.params.IVLen
	plainLen := len(innerIPPacket) + padLen + trailerLen
	packetLen := framingLen + plainLen + o.params.ICVLen
	nonceLen := o.aead.NonceSize()
	storage := make([]byte, nonceLen+framingLen+plainLen, nonceLen+packetLen)
	nonce := storage[:nonceLen]
	out := storage[nonceLen : nonceLen+framingLen+plainLen]
	binary.BigEndian.PutUint32(out[0:4], o.spi)
	binary.BigEndian.PutUint32(out[4:8], uint32(seq))
	binary.BigEndian.PutUint64(out[8:framingLen], seq) // unique per packet, monotonic

	plain := out[framingLen:]
	copy(plain, innerIPPacket)
	for i := 1; i <= padLen; i++ {
		plain[len(innerIPPacket)+i-1] = byte(i)
	}
	plain[len(plain)-2] = byte(padLen)
	plain[len(plain)-1] = nextHeader

	copy(nonce, o.salt)
	copy(nonce[len(o.salt):], out[headerLen:framingLen])
	aad := out[:headerLen]
	return o.aead.Seal(out[:framingLen], nonce, plain, aad), nil
}

// nextSeq atomically allocates the next sequence number, the only state
// Seal needs to serialize.
func (o *OutboundSA) nextSeq() (uint64, error) {
	seq := o.seq.Add(1)
	if seq > 0xffffffff {
		// No ESN: once the 32-bit sequence space is exhausted this SA is
		// unusable and the session must be re-established or rekeyed.
		return 0, fmt.Errorf("esp: sequence number space exhausted, SA must be re-established")
	}
	return seq, nil
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
	in.mu.Lock()
	err := in.window.check(seq)
	in.mu.Unlock()
	if err != nil {
		return nil, 0, err
	}

	iv := pkt[headerLen : headerLen+in.params.IVLen]
	ciphertext := pkt[headerLen+in.params.IVLen:]
	nonce := append(append([]byte{}, in.salt...), iv...)
	aad := pkt[:headerLen]

	// The AEAD compute itself touches no shared state, so it runs
	// unlocked — this is the expensive part, and the whole point of
	// checking once before it (fail fast) and again after (see below) is
	// to avoid holding the lock for its duration.
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

	// Re-check under the same lock as commit: another goroutine may have
	// committed this exact sequence, or advanced the window far enough
	// to make it stale, while this decrypt was in flight. Without this,
	// two concurrent decrypts of the same replayed packet could both
	// pass the first check and both get delivered.
	in.mu.Lock()
	err = in.window.check(seq)
	if err == nil {
		in.window.commit(seq)
	}
	in.mu.Unlock()
	if err != nil {
		return nil, 0, err
	}
	return plain[:len(plain)-2-padLen], nextHeader, nil
}
