package esp

import "fmt"

// DefaultReplayWindow is deliberately wider than the minimum interoperable
// window. RFC 4303 section 3.4.3 says receivers should increase the window in
// high-speed environments; multicore IPsec senders routinely reorder bursts
// by more than the 32-packet minimum before they reach userspace.
const DefaultReplayWindow uint32 = 4096

// replayWindow is an XFRM-style circular anti-replay bitmap. A zero window
// disables replay checking, matching strongSwan's replay_window = 0 behavior.
type replayWindow struct {
	window uint32
	last   uint32
	mask   []uint64
}

func newReplayWindow(window uint32) replayWindow {
	return replayWindow{window: window, mask: make([]uint64, (uint64(window)+63)/64)}
}

func (w *replayWindow) check(seq uint32) error {
	if w.window == 0 {
		return nil
	}
	if seq == 0 {
		return fmt.Errorf("esp: sequence number 0 is invalid")
	}
	if w.last == 0 || seq > w.last {
		return nil
	}
	diff := w.last - seq
	if diff >= w.window {
		return fmt.Errorf("esp: sequence %d too old (window is %d packets behind %d)", seq, w.window, w.last)
	}
	if w.set(w.bit(w.last, diff)) {
		return fmt.Errorf("esp: sequence %d replayed", seq)
	}
	return nil
}

func (w *replayWindow) commit(seq uint32) {
	if w.window == 0 {
		return
	}
	var bit uint32
	if w.last == 0 {
		w.last, bit = seq, (seq-1)%w.window
	} else if seq > w.last {
		diff := seq - w.last
		if diff >= w.window {
			clear(w.mask)
		} else {
			pos := (w.last - 1) % w.window
			for i := uint32(1); i < diff; i++ {
				w.clear((pos + i) % w.window)
			}
		}
		w.last, bit = seq, (seq-1)%w.window
	} else {
		bit = w.bit(w.last, w.last-seq)
	}
	w.mark(bit)
}

func (w *replayWindow) bit(last, diff uint32) uint32 {
	pos := (last - 1) % w.window
	return (pos + w.window - diff) % w.window
}
func (w *replayWindow) set(bit uint32) bool { return w.mask[bit/64]&(uint64(1)<<(bit%64)) != 0 }
func (w *replayWindow) mark(bit uint32)     { w.mask[bit/64] |= uint64(1) << (bit % 64) }
func (w *replayWindow) clear(bit uint32)    { w.mask[bit/64] &^= uint64(1) << (bit % 64) }
