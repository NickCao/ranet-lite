package esp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 7634 Appendix A publishes a complete tunnel-mode ChaCha20-Poly1305
// ESP packet. Opening its ESP wire image guards the SPI/sequence AAD, explicit
// IV, ciphertext, tag, padding, pad length, and Next Header together.
func TestRFC7634ESPWireImage(t *testing.T) {
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3")
	packet := mustHex(t, "01020304000000051011121314151617"+
		"24039428b97f417e3c13753a4f05087b67c352e6a7fab1b982d466ef407ae5c6"+
		"14ee8099d52844eb61aa95dfab4c02f72aa71e7c4c4f64c9befe2facc638e8f3"+
		"cbec163fac469b502773f6fb94e664da9165b82829f641e0"+
		"76aaa8266b7fb0f7b11b369907e1ad43")
	want := mustHex(t, "45000054a6f200004001e778c6336405c000020508005b7a3a080000553bec10"+
		"0007362708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223"+
		"2425262728292a2b2c2d2e2f3031323334353637")
	in, err := NewInbound(ChildSA{EncrID: ENCRChaCha20Poly1305, LocalSPI: 0x01020304, InboundKey: key})
	if err != nil {
		t.Fatal(err)
	}
	plain, nextHeader, err := in.Open(packet)
	if err != nil {
		t.Fatal(err)
	}
	if nextHeader != NextHeaderIPv4 || !bytes.Equal(plain, want) {
		t.Fatalf("RFC 7634 packet decoded to next-header %d, plaintext %x", nextHeader, plain)
	}
}

// This fixed AES-GCM packet exercises RFC 4106's complete ESP construction,
// not merely a local encrypt/decrypt round trip.
func TestRFC4106ESPWireImage(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f10111213")
	want := mustHex(t, "010203040000000100000000000000010c00b9b18f251e201fc6e81e37c3b1abf1d5002d1ae464e91ab3d134327602fe5e5ec36e3774fa67")
	out, err := NewOutbound(ChildSA{EncrID: ENCRAESGCM16, EncrKeyBits: 128, RemoteSPI: 0x01020304, OutboundKey: key})
	if err != nil {
		t.Fatal(err)
	}
	got, err := out.Seal([]byte("RFC 4106 AES-GCM ESP"), NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("RFC 4106 wire image = %x", got)
	}
}

func TestProactivePacketCountRekey(t *testing.T) {
	out, err := NewOutbound(testChild(t))
	if err != nil {
		t.Fatal(err)
	}
	var called atomic.Int32
	out.SetRekeyCallback(func() { called.Add(1) })
	out.seq.Store(ProactiveRekeySequence - 1)
	if _, err := out.Seal(nil, NextHeaderIPv4); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Seal(nil, NextHeaderIPv4); err != nil {
		t.Fatal(err)
	}
	if got := called.Load(); got != 1 {
		t.Fatalf("rekey callback called %d times, want once", got)
	}
}

func TestReservedSequenceRangesRemainContiguousWhenSealedOutOfOrder(t *testing.T) {
	out, err := NewOutbound(testChild(t))
	if err != nil {
		t.Fatal(err)
	}
	first, err := out.ReserveSequenceRange(2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := out.ReserveSequenceRange(2)
	if err != nil {
		t.Fatal(err)
	}

	// Complete the later worker first. Reservation order, rather than
	// goroutine scheduling or AEAD completion order, determines sequences.
	var got []uint32
	for _, r := range []*SequenceRange{second, first} {
		for range 2 {
			packet, err := r.Seal(nil, NextHeaderIPv4)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, binary.BigEndian.Uint32(packet[4:8]))
		}
	}
	want := []uint32{3, 4, 1, 2}
	if !slices.Equal(got, want) {
		t.Fatalf("sealed sequences = %v, want %v", got, want)
	}
	if _, err := first.Seal(nil, NextHeaderIPv4); err == nil {
		t.Fatal("exhausted sequence range accepted another packet")
	}
}

func testChild(t *testing.T) ChildSA {
	t.Helper()
	key := make([]byte, 20) // AES-128-GCM: 16-byte key + 4-byte salt
	rand.Read(key)
	return ChildSA{
		EncrID: 20, EncrKeyBits: 128,
		LocalSPI: 0x11111111, RemoteSPI: 0x22222222,
		InboundKey: key, OutboundKey: key,
	}
}

func TestRoundTrip(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	}, WithReplayWindow(4096))
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello from the other side of the tunnel")
	pkt, err := out.Seal(payload, NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}
	got, nh, err := in.Open(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if nh != NextHeaderIPv4 {
		t.Fatalf("next header = %d, want %d", nh, NextHeaderIPv4)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}
}

func TestAuthenticatedMalformedPacketConsumesSequence(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits, LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey})
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, headerLen+out.params.IVLen)
	binary.BigEndian.PutUint32(packet[0:4], out.spi)
	binary.BigEndian.PutUint32(packet[4:8], 1)
	binary.BigEndian.PutUint64(packet[8:16], 1)
	nonce := append(append([]byte(nil), out.salt...), packet[8:16]...)
	packet = out.aead.Seal(packet, nonce, []byte{0, 3, NextHeaderIPv4}, packet[:headerLen])
	if _, _, err := in.Open(packet); err == nil {
		t.Fatal("accepted malformed authenticated trailer")
	}
	in.mu.Lock()
	err = in.window.check(1)
	in.mu.Unlock()
	if err == nil {
		t.Fatal("malformed authenticated packet did not consume its sequence number")
	}
}

func TestRoundTripChaCha20Poly1305(t *testing.T) {
	key := make([]byte, 36) // 32-byte key + 4-byte salt
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	child := ChildSA{
		EncrID:   ENCRChaCha20Poly1305,
		LocalSPI: 0x11111111, RemoteSPI: 0x22222222,
		InboundKey: key, OutboundKey: key,
	}
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("chacha20-poly1305 packet")
	pkt, err := out.Seal(payload, NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}
	got, nh, err := in.Open(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if nh != NextHeaderIPv4 || !bytes.Equal(got, payload) {
		t.Fatalf("round trip mismatch: header %d, payload %q", nh, got)
	}
}

func TestSealAllocations(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1400)
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := out.Seal(payload, NextHeaderIPv4); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 1 {
		t.Fatalf("Seal allocated %.1f times per packet, want at most one output buffer", allocs)
	}
}

func TestReplayRejected(t *testing.T) {
	child := testChild(t)
	out, _ := NewOutbound(child)
	in, _ := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	pkt, _ := out.Seal([]byte("one"), NextHeaderIPv4)
	if _, _, err := in.Open(pkt); err != nil {
		t.Fatalf("first delivery should succeed: %v", err)
	}
	if _, _, err := in.Open(pkt); err == nil {
		t.Fatal("replayed packet was accepted")
	}
}

func TestAuthenticatedPacketsCommitInReceiveOrder(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	packets := make([][]byte, 64)
	for i := range packets {
		packets[i], err = out.Seal([]byte{byte(i)}, NextHeaderIPv4)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Model a later worker completing first. Authentication alone must not
	// advance the replay window far enough to reject the earlier batch.
	later, err := in.Authenticate(packets[len(packets)-1])
	if err != nil {
		t.Fatal(err)
	}
	earlier, err := in.Authenticate(packets[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := earlier.Commit(); err != nil {
		t.Fatalf("commit earlier packet: %v", err)
	}
	if _, _, err := later.Commit(); err != nil {
		t.Fatalf("commit later packet: %v", err)
	}
}

func TestAuthenticatedPacketCommitRejectsReplay(t *testing.T) {
	child := testChild(t)
	out, _ := NewOutbound(child)
	in, _ := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	packet, _ := out.Seal([]byte("one"), NextHeaderIPv4)
	first, err := in.Authenticate(packet)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := in.Authenticate(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := duplicate.Commit(); err == nil {
		t.Fatal("second commit of an authenticated replay succeeded")
	}
}

// TestReplayWindowWideReordering exercises the multi-word bitmap directly
// (bypassing real ESP/AEAD): sequences arriving thousands of positions out
// of order, as observed in practice under highly parallel real-world
// traffic (e.g. iperf3 -P 8 sharing one SA's sequence space across
// multiple flows/CPU cores), must still be accepted as long as they're
// within windowSize — and exact duplicates, even far apart across a large
// window advance, must still be rejected.
func TestReplayWindowWideReordering(t *testing.T) {
	const window = 4096
	w := newReplayWindow(window)

	// Establish a high watermark.
	if err := w.check(10000); err != nil {
		t.Fatalf("first packet should be accepted: %v", err)
	}
	w.commit(10000)

	// A packet ~3000 sequence numbers behind is well within a 64-packet
	// window's rejection range but must be accepted by the wider window.
	late := uint32(10000 - 3000)
	if err := w.check(late); err != nil {
		t.Fatalf("packet %d positions behind should be accepted with a %d window: %v", 3000, window, err)
	}
	w.commit(late)

	// The same late packet replayed again must still be rejected.
	if err := w.check(late); err == nil {
		t.Fatal("exact duplicate of a far-behind packet was accepted")
	}

	// A packet beyond windowSize behind must be rejected as too old.
	tooOld := uint32(10000 - window - 1)
	if err := w.check(tooOld); err == nil {
		t.Fatal("packet beyond the window was accepted")
	}

	// Advancing last by more than windowSize (a large jump forward, e.g.
	// after a burst) must not retain stale bits from before the jump: a
	// sequence that was legitimately received just before the jump must
	// now correctly read as "too old" rather than incorrectly "already
	// seen" or accepted twice.
	w.commit(10000 + window + 500)
	if err := w.check(10000); err == nil {
		t.Fatal("a sequence far behind after a large jump should be rejected as too old, not silently accepted")
	}
}

func TestReplayWindowZeroDisablesChecking(t *testing.T) {
	w := newReplayWindow(0)
	if err := w.check(0); err != nil {
		t.Fatalf("disabled replay window rejected sequence zero: %v", err)
	}
	w.commit(0)
}

// TestSealConcurrentUniqueSeq guards the split between atomic sequence
// allocation and the actual AEAD compute (unlocked, safe for concurrent use) in
// Seal: many goroutines sealing concurrently must never collide on a
// sequence number/IV, and the receiver must decrypt every one of them
// (Open, run sequentially here, doesn't care what order Seal calls
// completed in — only that all resulting sequence numbers are distinct
// and within the replay window relative to each other).
func TestSealConcurrentUniqueSeq(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	}, WithReplayWindow(4096))
	if err != nil {
		t.Fatal(err)
	}

	const n = 200
	pkts := make([][]byte, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pkt, err := out.Seal([]byte(fmt.Sprintf("packet-%d", i)), NextHeaderIPv4)
			if err != nil {
				t.Errorf("Seal: %v", err)
				return
			}
			pkts[i] = pkt
		}(i)
	}
	wg.Wait()

	seen := map[uint32]bool{}
	for i, pkt := range pkts {
		if pkt == nil {
			continue
		}
		seq := binary.BigEndian.Uint32(pkt[4:8])
		if seen[seq] {
			t.Fatalf("packet %d: sequence number %d reused", i, seq)
		}
		seen[seq] = true
		if _, _, err := in.Open(pkt); err != nil {
			t.Fatalf("packet %d (seq %d): %v", i, seq, err)
		}
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct sequence numbers, want %d", len(seen), n)
	}
}

// TestOpenConcurrent seals a batch of distinct packets up front (as a
// single-threaded sender would), then opens all of them concurrently —
// exercising Open's locked-check/unlocked-decrypt/locked-recheck-commit
// split under the race detector. Every packet must decrypt successfully
// exactly once.
func TestOpenConcurrent(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	}, WithReplayWindow(4096))
	if err != nil {
		t.Fatal(err)
	}

	const n = 200
	pkts := make([][]byte, n)
	for i := range pkts {
		pkt, err := out.Seal([]byte(fmt.Sprintf("packet-%d", i)), NextHeaderIPv4)
		if err != nil {
			t.Fatal(err)
		}
		pkts[i] = pkt
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed int
	for _, pkt := range pkts {
		wg.Add(1)
		go func(pkt []byte) {
			defer wg.Done()
			if _, _, err := in.Open(pkt); err != nil {
				mu.Lock()
				failed++
				mu.Unlock()
				t.Errorf("concurrent Open: %v", err)
			}
		}(pkt)
	}
	wg.Wait()
	if failed != 0 {
		t.Fatalf("%d/%d concurrent opens failed", failed, n)
	}
}

// TestOpenConcurrentReplayRejected races many goroutines opening the
// *exact same* packet simultaneously: exactly one must succeed (the
// first-check optimization racing the second locked check-and-commit
// must never let two winners through).
func TestOpenConcurrentReplayRejected(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := out.Seal([]byte("replay me"), NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}

	const n = 50
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := in.Open(pkt); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("got %d successful opens of the same packet, want exactly 1", got)
	}
}

func TestTamperedPacketRejected(t *testing.T) {
	child := testChild(t)
	out, _ := NewOutbound(child)
	in, _ := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	pkt, _ := out.Seal([]byte("untouched"), NextHeaderIPv4)
	pkt[len(pkt)-1] ^= 0xff
	if _, _, err := in.Open(pkt); err == nil {
		t.Fatal("tampered packet was accepted")
	}
}
