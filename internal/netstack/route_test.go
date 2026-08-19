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
	raw[3] = byte(len(raw))
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
	if _, _, _, ok := addrsOf(make([]byte, 20)); ok {
		t.Fatal("expected reject on invalid IPv4 length")
	}
	invalidIPv6 := make([]byte, 41)
	invalidIPv6[0] = 0x60
	if _, _, _, ok := addrsOf(invalidIPv6); ok {
		t.Fatal("expected reject on invalid IPv6 length")
	}
}

// TestRouteTableTrieRealBranching forces the destination trie to actually
// fork: several prefixes share increasingly long common prefixes, which
// the old linear scan never had to distinguish (it just compared each
// entry independently) but which exercises insertDest's branch-node
// creation directly. Every prefix here differs in its *installed*
// specificity, so each must resolve to exactly the one that covers it
// most precisely, regardless of how the trie chose to structure itself
// internally.
func TestRouteTableTrieRealBranching(t *testing.T) {
	rt := NewRouteTable()
	root := NewPeer("root", nil, nil)     // 10.0.0.0/8
	mid := NewPeer("mid", nil, nil)       // 10.64.0.0/10
	narrow := NewPeer("narrow", nil, nil) // 10.64.5.0/24
	other := NewPeer("other", nil, nil)   // 10.128.0.0/9 -- diverges from mid/narrow high up

	rt.Set(netip.Prefix{}, mustPrefix("10.0.0.0/8"), root)
	rt.Set(netip.Prefix{}, mustPrefix("10.64.0.0/10"), mid)
	rt.Set(netip.Prefix{}, mustPrefix("10.64.5.0/24"), narrow)
	rt.Set(netip.Prefix{}, mustPrefix("10.128.0.0/9"), other)

	cases := []struct {
		addr string
		want *Peer
	}{
		{"10.64.5.7", narrow}, // matches all four ancestors; most specific wins
		{"10.64.9.1", mid},    // inside mid, outside narrow
		{"10.200.0.1", other}, // inside other, outside mid/narrow
		{"10.1.2.3", root},    // only the broadest covers it
	}
	for _, c := range cases {
		peer, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr(c.addr))
		if !ok || peer != c.want {
			t.Fatalf("lookup(%s): got %v, %v; want %s", c.addr, peer, ok, c.want.ID)
		}
	}
	if _, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr("11.0.0.1")); ok {
		t.Fatal("expected no route outside 10.0.0.0/8 entirely")
	}
}

// TestRouteTableTrieCompactionPreservesSiblings removes one of two
// routes that fork from a shared synthetic branch node (neither 10.0.0.0/9
// nor 10.128.0.0/9 has an ancestor/descendant relationship with the
// other -- inserting both forces insertDest to create a branch node with
// no route of its own, just to fork them apart) and verifies the
// remaining sibling still resolves correctly afterward, i.e. removeNode's
// splice-and-recurse-upward compaction doesn't corrupt anything besides
// the route actually being removed.
func TestRouteTableTrieCompactionPreservesSiblings(t *testing.T) {
	rt := NewRouteTable()
	a := NewPeer("a", nil, nil)
	b := NewPeer("b", nil, nil)
	rt.Set(netip.Prefix{}, mustPrefix("10.0.0.0/9"), a)
	rt.Set(netip.Prefix{}, mustPrefix("10.128.0.0/9"), b)

	rt.Remove(netip.Prefix{}, mustPrefix("10.0.0.0/9"))

	if _, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr("10.1.2.3")); ok {
		t.Fatal("removed route still resolves")
	}
	peer, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr("10.129.0.1"))
	if !ok || peer != b {
		t.Fatalf("sibling route corrupted by removal: got %v, %v; want b, true", peer, ok)
	}

	// The now-pointless branch node forking these two apart should have
	// been compacted away entirely -- Debug should show exactly b's route.
	debug := rt.Debug()
	if len(debug) != 1 {
		t.Fatalf("expected exactly one remaining route after compaction, got %v", debug)
	}
}

// TestRouteTableTrieRemovePeerCompactsAcrossFamilies exercises RemovePeer
// walking both the IPv4 and IPv6 tries with several branching entries in
// each, confirming compaction leaves unrelated peers' routes intact in
// both address families.
func TestRouteTableTrieRemovePeerCompactsAcrossFamilies(t *testing.T) {
	rt := NewRouteTable()
	a := NewPeer("a", nil, nil)
	b := NewPeer("b", nil, nil)

	rt.Set(netip.Prefix{}, mustPrefix("10.0.0.0/9"), a)
	rt.Set(netip.Prefix{}, mustPrefix("10.128.0.0/9"), a)
	rt.Set(netip.Prefix{}, mustPrefix("10.64.0.0/10"), b)
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8:1::/48"), a)
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8:2::/48"), b)

	rt.RemovePeer(a)

	for _, addr := range []string{"10.1.2.3", "10.200.0.1", "2001:db8:1::5"} {
		if _, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr(addr)); ok {
			t.Fatalf("a's route for %s should be gone", addr)
		}
	}
	if peer, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr("10.64.1.1")); !ok || peer != b {
		t.Fatalf("b's IPv4 route should be unaffected, got %v, %v", peer, ok)
	}
	if peer, ok := rt.Lookup(mustAddr("1.2.3.4"), mustAddr("2001:db8:2::5")); !ok || peer != b {
		t.Fatalf("b's IPv6 route should be unaffected, got %v, %v", peer, ok)
	}
}
