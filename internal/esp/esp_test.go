package esp

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/NickCao/ranet-lite/internal/ike"
)

func testChild(t *testing.T) ike.ChildSA {
	t.Helper()
	key := make([]byte, 20) // AES-128-GCM: 16-byte key + 4-byte salt
	rand.Read(key)
	return ike.ChildSA{
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
	in, err := NewInbound(ike.ChildSA{
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

func TestReplayRejected(t *testing.T) {
	child := testChild(t)
	out, _ := NewOutbound(child)
	in, _ := NewInbound(ike.ChildSA{
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

func TestTamperedPacketRejected(t *testing.T) {
	child := testChild(t)
	out, _ := NewOutbound(child)
	in, _ := NewInbound(ike.ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	pkt, _ := out.Seal([]byte("untouched"), NextHeaderIPv4)
	pkt[len(pkt)-1] ^= 0xff
	if _, _, err := in.Open(pkt); err == nil {
		t.Fatal("tampered packet was accepted")
	}
}
