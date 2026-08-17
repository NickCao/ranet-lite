package babel

import "time"

// nowMicros is a 32-bit microsecond clock for RFC 9616 Timestamp sub-TLVs
// (§6: "expressed in units of one microsecond ... wrap around every 4295
// seconds"). We only ever difference two nearby samples of our own clock
// (see microDelta), never compare across nodes' clocks directly, so that
// ~71-minute wraparound is harmless as long as no single measurement spans
// it.
func nowMicros() uint32 {
	return uint32(time.Now().UnixMicro())
}

// microDelta computes b-a as a wraparound-safe signed duration, the same
// trick TCP uses for sequence numbers: reinterpreting the unsigned
// difference as a signed 32-bit value is correct as long as the true gap
// is less than half the modulus (here, well under the ~71-minute wrap).
func microDelta(b, a uint32) time.Duration {
	return time.Duration(int32(b-a)) * time.Microsecond
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
