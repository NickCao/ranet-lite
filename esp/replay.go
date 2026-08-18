package esp

import "fmt"

// windowSize is deliberately much larger than RFC 4303 Appendix A's
// 64-packet minimum: multiple concurrent flows share one ESP SA's single
// sequence number space (e.g. several parallel TCP connections, or a
// sender spreading encryption across multiple CPU cores/queues), which
// can legitimately reorder packets by thousands of positions under real
// load — a narrow window turns that ordinary reordering into false
// "replay" drops, i.e. real data loss, not just protection against an
// actual replay attack. The memory cost of a much wider bitmap is
// trivial (windowSize/8 bytes per SA), so there's little reason to keep
// it small.
const windowSize = 4096
const windowWords = windowSize / 64

// replayWindow is a windowSize-packet sliding anti-replay window, RFC
// 4303 Appendix A. check() only validates that a sequence number is
// admissible; commit() records it as received — split so a packet that
// fails AEAD authentication never advances or pollutes the window.
type replayWindow struct {
	last uint64
	mask [windowWords]uint64 // mask[i] bit j set => sequence (last - (i*64+j)) already received
}

// sequence reconstructs the high ESN bits from the current replay-window edge
// per RFC 4303 appendix A. This mirrors Linux XFRM's xfrm_replay_seqhi.
// The 64-bit result is authenticated before acceptance.
func (w *replayWindow) sequence(low uint32) uint64 {
	if w.last == 0 {
		return uint64(low)
	}
	high, lastLow := w.last>>32, uint32(w.last)
	bottom := lastLow - windowSize + 1
	if lastLow >= windowSize-1 {
		if low < bottom {
			high++
		}
	} else if low >= bottom && high > 0 {
		// The window wraps into the preceding 32-bit subspace.
		high--
	}
	if high == 0 && low == 0 {
		// Sequence zero is rejected by check; keep it in the initial subspace
		// so that it cannot be misclassified as a wrapped packet.
		return 0
	}
	return high<<32 | uint64(low)
}

func (w *replayWindow) check(seq uint64) error {
	if seq == 0 {
		return fmt.Errorf("esp: sequence number 0 is invalid")
	}
	s := seq
	if w.last == 0 {
		return nil // first packet ever seen on this SA
	}
	if s > w.last {
		return nil
	}
	diff := w.last - s
	if diff >= windowSize {
		return fmt.Errorf("esp: sequence %d too old (window is %d packets behind %d)", s, windowSize, w.last)
	}
	word, bit := diff/64, diff%64
	if w.mask[word]&(1<<bit) != 0 {
		return fmt.Errorf("esp: sequence %d replayed", s)
	}
	return nil
}

func (w *replayWindow) commit(seq uint64) {
	s := seq
	switch {
	case w.last == 0:
		w.mask[0] = 1
		w.last = s
	case s > w.last:
		w.shiftLeft(s - w.last)
		w.mask[0] |= 1
		w.last = s
	default:
		diff := w.last - s
		word, bit := diff/64, diff%64
		w.mask[word] |= 1 << bit
	}
}

// shiftLeft advances the window by shift positions: bit i (representing
// how far behind the old w.last a sequence is) must become bit i+shift
// (how far behind the new w.last, which is shift further ahead, that same
// sequence now is).
func (w *replayWindow) shiftLeft(shift uint64) {
	if shift >= windowSize {
		w.mask = [windowWords]uint64{}
		return
	}
	wordShift := int(shift / 64)
	bitShift := uint(shift % 64)
	var next [windowWords]uint64
	for i := windowWords - 1; i >= 0; i-- {
		srcIdx := i - wordShift
		if srcIdx < 0 {
			continue
		}
		next[i] = w.mask[srcIdx] << bitShift
		if bitShift > 0 && srcIdx-1 >= 0 {
			next[i] |= w.mask[srcIdx-1] >> (64 - bitShift)
		}
	}
	w.mask = next
}
