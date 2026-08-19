package babel

import (
	"net/netip"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

func TestRouteTableSweepGarbageCollectsExpiredState(t *testing.T) {
	rt := newRouteTable()
	neighbor := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	makeNeighborReachable(neighbor)
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	rt.update(neighbor, key, [8]byte{1}, 1, 1, time.Minute)
	rt.entries[key].selected.expiresAt = time.Now().Add(-time.Second)
	var installed bool
	rt.sweepExpired(func(got routeKey, selected *routeInfo) {
		installed = true
		if got != key || selected != nil {
			t.Fatalf("sweep callback = %v, %v; want %v, nil", got, selected, key)
		}
	})
	if !installed {
		t.Fatal("expired selected route was not retracted")
	}
	if len(rt.entries) != 0 {
		t.Fatalf("expired route state retained %d entries", len(rt.entries))
	}
}

func TestRouteTableNeighborExpiryDeletesEmptyEntry(t *testing.T) {
	rt := newRouteTable()
	neighbor := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	rt.update(neighbor, key, [8]byte{1}, 1, 1, time.Minute)
	rt.expireNeighbor(neighbor)
	if len(rt.entries) != 0 {
		t.Fatalf("neighbor expiry retained %d empty entries", len(rt.entries))
	}
}

func TestInfiniteLinkCostNeverBecomesReachable(t *testing.T) {
	if got := saturatingAdd(MetricInfinity, 1); got != MetricInfinity {
		t.Fatalf("infinity + 1 = %d, want infinity", got)
	}
	rt := newRouteTable()
	neighbor := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	_, selected := rt.update(neighbor, key, [8]byte{1}, 1, 1, time.Minute)
	if selected != nil {
		t.Fatalf("selected route without live Hello/IHU: %+v", selected)
	}
}
