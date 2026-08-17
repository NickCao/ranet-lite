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
