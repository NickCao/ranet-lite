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
	NextHeaderNone = 59

	headerLen = 8 // SPI + 32-bit Sequence Number
	// ProactiveRekeySequence leaves a 65536-packet safety margin before a
	// non-ESN SA's sequence space is exhausted.
	ProactiveRekeySequence = uint64(0xffffffff - 0xffff)
)

// OutboundSA encrypts packets for the direction this client originates.
// Sequence/IV assignment is atomic because Babel and the mesh may reserve
// packets from separate goroutines. Reusing a sequence/IV with AES-GCM would
// break confidentiality and authentication outright.
type OutboundSA struct {
	aead   cipher.AEAD
	params aeadParams
	salt   []byte
	spi    uint32

	seq       atomic.Uint64 // next sequence number to use; 0 is never sent (RFC 4303 §2.2)
	rekeyOnce sync.Once
	onRekey   func()
}

// SequenceRange is an ordered run of sequence numbers reserved from one SA.
// A range belongs to one worker: successive Seal calls consume its sequence
// numbers in order, while separate ranges can perform their AEAD work in
// parallel. Values can only be created by OutboundSA.ReserveSequenceRange, so
// callers cannot accidentally choose or reuse a nonce.
type SequenceRange struct {
	sa   *OutboundSA
	next uint64
	end  uint64
}

// SetRekeyCallback installs a one-shot notification fired when the outbound
// packet counter reaches ProactiveRekeySequence. Configure it before Seal is
// called concurrently.
func (o *OutboundSA) SetRekeyCallback(fn func()) { o.onRekey = fn }

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

// AuthenticatedPacket is an ESP packet whose SPI and AEAD tag have been
// verified, but whose sequence number has not yet been committed to the
// anti-replay window. Receive workers authenticate in parallel, then call
// Commit in wire-arrival order so scheduler timing cannot make a valid packet
// appear older than the replay window.
type AuthenticatedPacket struct {
	sa    *InboundSA
	seq   uint32
	plain []byte
}

// InboundOption configures inbound ESP processing.
type InboundOption func(*InboundSA)

// WithReplayWindow sets the anti-replay window. A zero value disables replay
// checking, matching strongSwan's replay_window = 0 behavior.
func WithReplayWindow(window uint32) InboundOption {
	return func(in *InboundSA) { in.window = newReplayWindow(window) }
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

func NewInbound(child ChildSA, options ...InboundOption) (*InboundSA, error) {
	aead, params, err := newESPAEAD(child.EncrID, child.EncrKeyBits, child.InboundKey)
	if err != nil {
		return nil, err
	}
	in := &InboundSA{
		aead: aead, params: params,
		salt:   child.InboundKey[params.keyLen:],
		spi:    child.LocalSPI,
		window: newReplayWindow(DefaultReplayWindow),
	}
	for _, option := range options {
		option(in)
	}
	return in, nil
}

// Seal wraps one tunnel-mode IP packet (nextHeader identifies its version,
// NextHeaderIPv4/IPv6) into a full ESP packet ready for UDP encapsulation.
// It is the single-packet convenience path; the data plane reserves ranges so
// whole TUN batches can encrypt concurrently without allocating their ESP
// sequence numbers in scheduler-dependent order.
func (o *OutboundSA) Seal(innerIPPacket []byte, nextHeader byte) ([]byte, error) {
	seq, _, err := o.reserveSequenceNumbers(1)
	if err != nil {
		return nil, err
	}
	return o.sealWithSequence(innerIPPacket, nextHeader, seq)
}

// ReserveSequenceRange atomically reserves count consecutive ESP sequence
// numbers. Reserving is cheap and may be serialized with packet intake; the
// returned range performs the expensive AEAD operations later and in parallel
// with other ranges.
func (o *OutboundSA) ReserveSequenceRange(count int) (*SequenceRange, error) {
	first, end, err := o.reserveSequenceNumbers(count)
	if err != nil {
		return nil, err
	}
	return &SequenceRange{sa: o, next: first, end: end}, nil
}

func (o *OutboundSA) reserveSequenceNumbers(count int) (uint64, uint64, error) {
	if count <= 0 {
		return 0, 0, fmt.Errorf("esp: sequence range must contain at least one packet")
	}
	n := uint64(count)
	end := o.seq.Add(n)
	first := end - n + 1
	if end >= ProactiveRekeySequence && first <= 0xffffffff && o.onRekey != nil {
		o.rekeyOnce.Do(o.onRekey)
	}
	if end > 0xffffffff {
		// No ESN: do not return even the in-range prefix of a reservation that
		// crosses the boundary. The caller must move the whole batch to a fresh
		// SA rather than partially transmitting it.
		return 0, 0, fmt.Errorf("esp: sequence number space exhausted, SA must be re-established")
	}
	return first, end, nil
}

// Seal consumes the next sequence number in this range and encrypts one
// tunnel-mode packet. A SequenceRange is deliberately single-worker; parallel
// callers should reserve separate ranges from the OutboundSA.
func (r *SequenceRange) Seal(innerIPPacket []byte, nextHeader byte) ([]byte, error) {
	if r == nil || r.sa == nil || r.next > r.end {
		return nil, fmt.Errorf("esp: reserved sequence range exhausted")
	}
	seq := r.next
	r.next++
	return r.sa.sealWithSequence(innerIPPacket, nextHeader, seq)
}

func (o *OutboundSA) sealWithSequence(innerIPPacket []byte, nextHeader byte, seq uint64) ([]byte, error) {

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

// Authenticate validates the SPI and AEAD tag without advancing the replay
// window. The inexpensive preliminary replay check rejects obvious replays;
// Commit repeats that check atomically with advancing the window after
// parallel authentication completes.
func (in *InboundSA) Authenticate(pkt []byte) (*AuthenticatedPacket, error) {
	if len(pkt) < headerLen+in.params.IVLen+in.params.ICVLen {
		return nil, fmt.Errorf("esp: packet too short")
	}
	spi := binary.BigEndian.Uint32(pkt[0:4])
	if spi != in.spi {
		return nil, fmt.Errorf("esp: SPI mismatch (got %08x, want %08x)", spi, in.spi)
	}
	seq := binary.BigEndian.Uint32(pkt[4:8])
	in.mu.Lock()
	err := in.window.check(seq)
	in.mu.Unlock()
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("esp: authentication failed: %w", err)
	}
	return &AuthenticatedPacket{sa: in, seq: seq, plain: plain}, nil
}

// Commit advances the anti-replay window and interprets the authenticated ESP
// trailer. Authentication consumes the sequence number even if the trailer is
// malformed (RFC 4303 section 3.4.3), so the commit precedes trailer parsing.
func (p *AuthenticatedPacket) Commit() ([]byte, byte, error) {
	if p == nil || p.sa == nil {
		return nil, 0, fmt.Errorf("esp: nil authenticated packet")
	}
	// Authentication, rather than successful trailer interpretation, consumes
	// the sequence number (RFC 4303 section 3.4.3).
	p.sa.mu.Lock()
	err := p.sa.window.check(p.seq)
	if err == nil {
		p.sa.window.commit(p.seq)
	}
	p.sa.mu.Unlock()
	if err != nil {
		return nil, 0, err
	}
	plain := p.plain
	if len(plain) < 2 {
		return nil, 0, fmt.Errorf("esp: plaintext too short")
	}
	padLen := int(plain[len(plain)-2])
	nextHeader := plain[len(plain)-1]
	if padLen+2 > len(plain) {
		return nil, 0, fmt.Errorf("esp: invalid padding")
	}
	for i, value := range plain[len(plain)-2-padLen : len(plain)-2] {
		if value != byte(i+1) {
			return nil, 0, fmt.Errorf("esp: invalid padding contents")
		}
	}

	return plain[:len(plain)-2-padLen], nextHeader, nil
}

// Open is the single-packet convenience path. Batch receive pipelines use
// Authenticate and Commit separately to parallelize AEAD work while retaining
// deterministic replay-window order.
func (in *InboundSA) Open(pkt []byte) ([]byte, byte, error) {
	authenticated, err := in.Authenticate(pkt)
	if err != nil {
		return nil, 0, err
	}
	return authenticated.Commit()
}
