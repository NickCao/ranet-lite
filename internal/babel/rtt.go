package babel

import "time"

// nowMillis is a 32-bit millisecond clock for RFC 9616 Timestamp sub-TLVs.
// It wraps every ~49.7 days; since we only ever subtract two nearby
// samples (this node's own clock, never compared across nodes), wraparound
// is harmless as long as no single RTT measurement spans that long.
func nowMillis() uint32 {
	return uint32(time.Now().UnixMilli())
}

// CostParams configures RTT-based costing, RFC 9616. Defaults mirror a
// typical tunnel-mesh deployment (see internal/babel doc comment): a fixed
// base rxcost plus up to RTTCost additional cost scaled linearly between
// RTTMin and RTTMax.
type CostParams struct {
	RxCost  uint16
	RTTMin  time.Duration
	RTTMax  time.Duration
	RTTCost uint16
}

func DefaultCostParams() CostParams {
	return CostParams{
		RxCost:  32,
		RTTMin:  0,
		RTTMax:  1024 * time.Millisecond,
		RTTCost: 1024,
	}
}

// Cost implements the standard babeld/RFC 9616 RTT-cost formula: rxcost
// alone below RTTMin, rxcost+RTTCost at/above RTTMax, linear in between.
func (p CostParams) Cost(rtt time.Duration, haveRTT bool) uint16 {
	if !haveRTT || p.RTTCost == 0 || p.RTTMax <= p.RTTMin {
		return p.RxCost
	}
	if rtt <= p.RTTMin {
		return p.RxCost
	}
	if rtt >= p.RTTMax {
		return saturatingAdd(p.RxCost, p.RTTCost)
	}
	// int64 nanosecond products (e.g. 1024 * 1s) overflow uint32 well
	// before the division brings the result back into range.
	extra := uint64(p.RTTCost) * uint64(rtt-p.RTTMin) / uint64(p.RTTMax-p.RTTMin)
	return saturatingAdd(p.RxCost, uint16(extra))
}

func saturatingAdd(a, b uint16) uint16 {
	sum := uint32(a) + uint32(b)
	if sum >= uint32(MetricInfinity) {
		return MetricInfinity - 1
	}
	return uint16(sum)
}
