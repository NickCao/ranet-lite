package netstack

import (
	"net/netip"
	"testing"
)

func mustAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestRouteTableOrdinaryLookup(t *testing.T) {
	rt := NewRouteTable()
	a := NewPeer("a", nil, nil)
	b := NewPeer("b", nil, nil)

	rt.Set(netip.Prefix{}, mustPrefix("10.0.0.0/8"), a)
	rt.Set(netip.Prefix{}, mustPrefix("10.1.0.0/16"), b)

	// Longest destination prefix wins regardless of order installed.
	peer, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr("10.1.2.3"))
	if !ok || peer != b {
		t.Fatalf("got %v, %v; want b, true", peer, ok)
	}
	peer, ok = rt.Lookup(mustAddr("1.2.3.4"), mustAddr("10.9.9.9"))
	if !ok || peer != a {
		t.Fatalf("got %v, %v; want a, true", peer, ok)
	}
	if _, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr("192.168.1.1")); ok {
		t.Fatal("expected no route")
	}
}

func TestRouteTableSourceSpecificTakesPriorityAtEqualDestSpecificity(t *testing.T) {
	rt := NewRouteTable()
	any := NewPeer("any", nil, nil)
	specific := NewPeer("specific", nil, nil)

	dest := mustPrefix("2001:db8::/64")
	rt.Set(netip.Prefix{}, dest, any)
	rt.Set(mustPrefix("2001:db8:1::/48"), dest, specific)

	// Source falls inside the source-specific entry's prefix: it must win
	// even though both entries match the same destination.
	peer, ok := rt.Lookup(mustAddr("2001:db8:1::5"), mustAddr("2001:db8::1"))
	if !ok || peer != specific {
		t.Fatalf("got %v, %v; want specific, true", peer, ok)
	}

	// Source falls outside the source-specific entry: falls back to the
	// any-source (ordinary) route, not "no match".
	peer, ok = rt.Lookup(mustAddr("2001:db8:2::5"), mustAddr("2001:db8::1"))
	if !ok || peer != any {
		t.Fatalf("got %v, %v; want any, true", peer, ok)
	}
}

func TestRouteTableDestSpecificityBeatsSourceSpecificity(t *testing.T) {
	rt := NewRouteTable()
	broad := NewPeer("broad", nil, nil)
	narrow := NewPeer("narrow", nil, nil)

	// A source-specific route to a *less specific* destination must not
	// beat an any-source route to a *more specific* destination — the
	// destination match is resolved first, per
	// draft-ietf-babel-source-specific.
	rt.Set(mustPrefix("2001:db8:1::/48"), mustPrefix("2001:db8::/32"), broad)
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8::/48"), narrow)

	peer, ok := rt.Lookup(mustAddr("2001:db8:1::5"), mustAddr("2001:db8::1"))
	if !ok || peer != narrow {
		t.Fatalf("got %v, %v; want narrow (more specific destination), true", peer, ok)
	}
}

func TestRouteTableSetReplacesSameKey(t *testing.T) {
	rt := NewRouteTable()
	a := NewPeer("a", nil, nil)
	b := NewPeer("b", nil, nil)
	dest := mustPrefix("10.0.0.0/24")

	rt.Set(netip.Prefix{}, dest, a)
	rt.Set(netip.Prefix{}, dest, b) // same (src, dst) key, must replace, not duplicate

	if debug := rt.Debug(); len(debug) != 1 {
		t.Fatalf("expected exactly one entry after replace, got %v", debug)
	}
	peer, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr("10.0.0.5"))
	if !ok || peer != b {
		t.Fatalf("got %v, %v; want b, true", peer, ok)
	}
}

func TestRouteTableSourceSpecificAndOrdinaryCoexistIndependently(t *testing.T) {
	rt := NewRouteTable()
	any := NewPeer("any", nil, nil)
	specific := NewPeer("specific", nil, nil)
	dest := mustPrefix("10.0.0.0/24")

	rt.Set(netip.Prefix{}, dest, any)
	rt.Set(mustPrefix("192.168.0.0/16"), dest, specific)
	if debug := rt.Debug(); len(debug) != 2 {
		t.Fatalf("expected both entries to coexist, got %v", debug)
	}

	// Removing the source-specific one must not disturb the ordinary one.
	rt.Remove(mustPrefix("192.168.0.0/16"), dest)
	peer, ok := rt.Lookup(mustAddr("192.168.1.1"), mustAddr("10.0.0.5"))
	if !ok || peer != any {
		t.Fatalf("got %v, %v; want any (fallback survives), true", peer, ok)
	}
}

func TestRouteTableRemovePeer(t *testing.T) {
	rt := NewRouteTable()
	a := NewPeer("a", nil, nil)
	b := NewPeer("b", nil, nil)
	rt.Set(netip.Prefix{}, mustPrefix("10.0.0.0/24"), a)
	rt.Set(mustPrefix("192.168.0.0/16"), mustPrefix("10.0.0.0/24"), a)
	rt.Set(netip.Prefix{}, mustPrefix("10.1.0.0/24"), b)

	rt.RemovePeer(a)

	if _, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr("10.0.0.5")); ok {
		t.Fatal("expected a's routes to be gone")
	}
	if _, ok := rt.Lookup(mustAddr("192.168.1.1"), mustAddr("10.0.0.5")); ok {
		t.Fatal("expected a's source-specific route to be gone too")
	}
	if peer, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr("10.1.0.5")); !ok || peer != b {
		t.Fatalf("b's route should be unaffected, got %v, %v", peer, ok)
	}
}

func TestAddrsOfIPv4(t *testing.T) {
	raw := make([]byte, 20)
	raw[0] = 0x45
	copy(raw[12:16], mustAddr("10.1.2.3").AsSlice())
	copy(raw[16:20], mustAddr("10.4.5.6").AsSlice())

	src, dst, nh, ok := addrsOf(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if src != mustAddr("10.1.2.3") || dst != mustAddr("10.4.5.6") {
		t.Fatalf("got src=%s dst=%s", src, dst)
	}
	if nh != 4 {
		t.Fatalf("next header = %d, want 4 (IPv4)", nh)
	}
}

func TestAddrsOfIPv6(t *testing.T) {
	raw := make([]byte, 40)
	raw[0] = 0x60
	copy(raw[8:24], mustAddr("2001:db8::1").AsSlice())
	copy(raw[24:40], mustAddr("2001:db8::2").AsSlice())

	src, dst, nh, ok := addrsOf(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if src != mustAddr("2001:db8::1") || dst != mustAddr("2001:db8::2") {
		t.Fatalf("got src=%s dst=%s", src, dst)
	}
	if nh != 41 {
		t.Fatalf("next header = %d, want 41 (IPv6)", nh)
	}
}

func TestAddrsOfRejectsShortOrUnknownPackets(t *testing.T) {
	if _, _, _, ok := addrsOf(nil); ok {
		t.Fatal("expected reject on empty input")
	}
	if _, _, _, ok := addrsOf([]byte{0x45, 0, 0}); ok {
		t.Fatal("expected reject on truncated IPv4 header")
	}
	if _, _, _, ok := addrsOf([]byte{0x00}); ok {
		t.Fatal("expected reject on unknown IP version")
	}
}
