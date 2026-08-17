package babel

import (
	"testing"
	"time"
)

func TestCostFormula(t *testing.T) {
	p := CostParams{RxCost: 32, RTTMin: 0, RTTMax: 1024 * time.Millisecond, RTTCost: 1024}

	if c := p.Cost(0, false); c != 32 {
		t.Errorf("no RTT sample: got %d, want 32", c)
	}
	if c := p.Cost(0, true); c != 32 {
		t.Errorf("rtt=0: got %d, want 32", c)
	}
	if c := p.Cost(2*time.Second, true); c != 32+1024 {
		t.Errorf("rtt above max: got %d, want %d", c, 32+1024)
	}
	if c := p.Cost(512*time.Millisecond, true); c != 32+512 {
		t.Errorf("rtt at midpoint: got %d, want %d", c, 32+512)
	}
}
