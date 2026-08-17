package esp

import "fmt"

// replayWindow is a 64-packet sliding anti-replay window, RFC 4303
// Appendix A. check() only validates that a sequence number is
// admissible; commit() records it as received — split so a packet that
// fails AEAD authentication never advances or pollutes the window.
type replayWindow struct {
	last uint64
	mask uint64 // bit i set => sequence (last - i) already received
}

func (w *replayWindow) check(seq uint32) error {
	if seq == 0 {
		return fmt.Errorf("esp: sequence number 0 is invalid")
	}
	s := uint64(seq)
	if w.last == 0 {
		return nil // first packet ever seen on this SA
	}
	if s > w.last {
		return nil
	}
	diff := w.last - s
	if diff >= 64 {
		return fmt.Errorf("esp: sequence %d too old (window is 64 packets behind %d)", s, w.last)
	}
	if w.mask&(1<<diff) != 0 {
		return fmt.Errorf("esp: sequence %d replayed", s)
	}
	return nil
}

func (w *replayWindow) commit(seq uint32) {
	s := uint64(seq)
	switch {
	case w.last == 0:
		w.last, w.mask = s, 1
	case s > w.last:
		shift := s - w.last
		if shift >= 64 {
			w.mask = 1
		} else {
			w.mask = (w.mask << shift) | 1
		}
		w.last = s
	default:
		w.mask |= 1 << (w.last - s)
	}
}
