package sadr

import (
	"net/netip"
	"testing"
)

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }

func TestTableLPMAndSADRSelection(t *testing.T) {
	var table Table[string]
	table.Set(netip.Prefix{}, prefix("2001:db8::/32"), "broad")
	table.Set(prefix("2001:db8:1::/48"), prefix("2001:db8::/32"), "source-specific")
	table.Set(netip.Prefix{}, prefix("2001:db8::/48"), "narrow")

	if got, ok := table.Lookup(addr("2001:db8:1::1"), addr("2001:db8::1")); !ok || got != "narrow" {
		t.Fatalf("got %q, %v; want narrow, true", got, ok)
	}
	if got, ok := table.Lookup(addr("2001:db8:1::1"), addr("2001:db8:2::1")); !ok || got != "source-specific" {
		t.Fatalf("got %q, %v; want source-specific, true", got, ok)
	}
	if got, ok := table.Lookup(addr("2001:db8:3::1"), addr("2001:db8:2::1")); !ok || got != "broad" {
		t.Fatalf("got %q, %v; want broad, true", got, ok)
	}
}

func TestTableRemoveValue(t *testing.T) {
	var table Table[string]
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), "remove")
	table.Set(prefix("192.0.2.0/24"), prefix("10.1.0.0/16"), "remove")
	table.Set(netip.Prefix{}, prefix("10.2.0.0/16"), "keep")

	table.RemoveValue("remove")
	if _, ok := table.Lookup(addr("192.0.2.1"), addr("10.1.0.1")); ok {
		t.Fatal("removed value still resolves")
	}
	if got, ok := table.Lookup(addr("192.0.2.1"), addr("10.2.0.1")); !ok || got != "keep" {
		t.Fatalf("got %q, %v; want keep, true", got, ok)
	}
}

func TestTableIPv4AndIPv6(t *testing.T) {
	var table Table[int]
	table.Set(netip.Prefix{}, prefix("192.0.2.0/24"), 4)
	table.Set(netip.Prefix{}, prefix("2001:db8::/32"), 6)

	if got, ok := table.Lookup(addr("198.51.100.1"), addr("192.0.2.1")); !ok || got != 4 {
		t.Fatalf("IPv4 lookup got %d, %v; want 4, true", got, ok)
	}
	if got, ok := table.Lookup(addr("2001:db8::2"), addr("2001:db8::1")); !ok || got != 6 {
		t.Fatalf("IPv6 lookup got %d, %v; want 6, true", got, ok)
	}
	if _, ok := table.Lookup(addr("198.51.100.1"), addr("2001:db9::1")); ok {
		t.Fatal("unexpected cross-family route")
	}
}

func TestTableFallsBackPastInapplicableDestination(t *testing.T) {
	var table Table[string]
	table.Set(netip.Prefix{}, prefix("2001:db8::/32"), "fallback")
	table.Set(prefix("fd00:1::/64"), prefix("2001:db8:1::/64"), "specific")

	if got, ok := table.Lookup(addr("fd00:2::1"), addr("2001:db8:1::1")); !ok || got != "fallback" {
		t.Fatalf("got %q, %v; want fallback, true", got, ok)
	}
	if got, ok := table.Lookup(addr("fd00:1::1"), addr("2001:db8:1::1")); !ok || got != "specific" {
		t.Fatalf("got %q, %v; want specific, true", got, ok)
	}
}
