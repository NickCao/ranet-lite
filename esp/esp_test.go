package esp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

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
	})
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

// TestReplayWindowWideReordering exercises the multi-word bitmap directly
// (bypassing real ESP/AEAD): sequences arriving thousands of positions out
// of order, as observed in practice under highly parallel real-world
// traffic (e.g. iperf3 -P 8 sharing one SA's sequence space across
// multiple flows/CPU cores), must still be accepted as long as they're
// within windowSize — and exact duplicates, even far apart across a large
// window advance, must still be rejected.
func TestReplayWindowWideReordering(t *testing.T) {
	var w replayWindow

	// Establish a high watermark.
	if err := w.check(10000); err != nil {
		t.Fatalf("first packet should be accepted: %v", err)
	}
	w.commit(10000)

	// A packet ~3000 sequence numbers behind is well within a 64-packet
	// window's rejection range but must be accepted by the wider window.
	late := uint32(10000 - 3000)
	if err := w.check(late); err != nil {
		t.Fatalf("packet %d positions behind should be accepted with a %d window: %v", 3000, windowSize, err)
	}
	w.commit(late)

	// The same late packet replayed again must still be rejected.
	if err := w.check(late); err == nil {
		t.Fatal("exact duplicate of a far-behind packet was accepted")
	}

	// A packet beyond windowSize behind must be rejected as too old.
	tooOld := uint32(10000 - windowSize - 1)
	if err := w.check(tooOld); err == nil {
		t.Fatal("packet beyond the window was accepted")
	}

	// Advancing last by more than windowSize (a large jump forward, e.g.
	// after a burst) must not retain stale bits from before the jump: a
	// sequence that was legitimately received just before the jump must
	// now correctly read as "too old" rather than incorrectly "already
	// seen" or accepted twice.
	w.commit(10000 + windowSize + 500)
	if err := w.check(10000); err == nil {
		t.Fatal("a sequence far behind after a large jump should be rejected as too old, not silently accepted")
	}
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
	})
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
	})
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
