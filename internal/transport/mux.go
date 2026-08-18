// Package transport owns the single UDP socket shared by the IKE control
// channel and UDP-encapsulated ESP data. ranet's strongSwan deployments
// force UDP encapsulation unconditionally (`encap = yes`) on the one
// explicit registry port — there is no separate NAT-T port and no
// floating: every IKE message, including the very first IKE_SA_INIT
// request, is prefixed with a 4-byte zero "non-ESP marker" (RFC 3948 /
// RFC 7296 §2.23), and ESP packets are sent bare (their SPI, always
// nonzero, disambiguates them from the marker on receive).
package transport

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const nonESPMarkerLen = 4

// espSendBatch bounds how many queued ESP packets sendESPLoop coalesces
// into one sendmmsg(2) call, and readBatchSize how many inbound datagrams
// readLoop reads with one recvmmsg(2) call. A CPU profile under load
// showed roughly half of all time spent in the write syscall alone — one
// syscall per packet — with AEAD encryption barely registering; the read
// side has the identical problem in the opposite direction: one
// ReadFromUDP syscall per incoming datagram is slow enough, under a fast
// enough real sender, to risk overflowing the kernel's UDP receive
// buffer — real, silent packet loss that happens before our replay
// window or anything else in this codebase ever sees the packet.
const (
	espSendBatch   = 128
	readBatchSize  = 128
	readBufferSize = 65536
	// espChanSize is deliberately generous: it's the buffer absorbing any
	// gap between how fast readLoop can now receive (batched, fast) and
	// how fast the consumer can decrypt+deliver (see cmd/ranet-lite's
	// parallel inbound worker pool) — too small and a burst overflows it,
	// which is real, permanent packet loss, not just added latency.
	espChanSize = 4096
)

// batchConn abstracts ipv4.PacketConn and ipv6.PacketConn's
// WriteBatch/ReadBatch: both Message types are aliases for the same
// underlying golang.org/x/net/internal/socket.Message, so either
// concrete type satisfies this identically.
type batchConn interface {
	WriteBatch(ms []ipv4.Message, flags int) (int, error)
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

// Mux is a UDP socket to exactly one peer, demultiplexing inbound packets
// into IKE and ESP streams and handling the initial-port -> NAT-T-port
// float ranet's strongSwan deployments always trigger (they set
// `encap = yes` unconditionally, RFC 7296 §2.23 note in ranet's vici config).
type Mux struct {
	conn       *net.UDPConn
	remoteIP   net.IP
	remotePort int
	batch      batchConn

	ikeCh  chan []byte
	espCh  chan []byte
	espOut chan []byte // queued outbound ESP packets awaiting a batched write
	// done is closed exactly once, on a fatal read error or Close() —
	// closing (unlike sending on a channel) wakes every blocked receiver,
	// not just one. RecvIKE and RecvESP run concurrently in normal use
	// (the DPD loop and the ESP receive loop), so a single-value error
	// channel would only ever notify whichever of them happened to be
	// selected first, leaking the other forever.
	done     chan struct{}
	doneOnce sync.Once
	doneErr  atomic.Value // error
	closed   atomic.Bool
}

// closeDone wakes every blocked Recv* call exactly once, regardless of
// whether it's triggered by a real read error or an explicit Close().
func (m *Mux) closeDone(err error) {
	m.doneOnce.Do(func() {
		m.doneErr.Store(err)
		close(m.done)
	})
}

// Dial opens the shared socket. localAddr may be "" to let the OS pick an
// ephemeral port on all interfaces. remoteAddr:remotePort is the peer's
// configured IKE endpoint — ranet's registry port, commonly non-standard
// (e.g. 13000) — and is the only port ever used; there is no separate
// NAT-T port and no floating.
func Dial(localAddr string, remoteIP net.IP, remotePort int) (*Mux, error) {
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve local addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("transport: listen: %w", err)
	}
	var batch batchConn
	if remoteIP.To4() != nil {
		batch = ipv4.NewPacketConn(conn)
	} else {
		batch = ipv6.NewPacketConn(conn)
	}
	m := &Mux{
		conn:       conn,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		batch:      batch,
		ikeCh:      make(chan []byte, 16),
		espCh:      make(chan []byte, espChanSize),
		espOut:     make(chan []byte, espChanSize),
		done:       make(chan struct{}),
	}
	go m.readLoop()
	go m.sendESPLoop()
	return m, nil
}

func (m *Mux) LocalAddr() net.Addr { return m.conn.LocalAddr() }

func (m *Mux) remoteAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: m.remoteIP, Port: m.remotePort}
}

// SendIKE writes one IKE message, always prefixed with the non-ESP marker
// — ranet forces UDP encapsulation unconditionally, so even the very first
// IKE_SA_INIT request must carry it; the responder isn't listening for a
// bare (unmarked) ISAKMP header on this port at all.
func (m *Mux) SendIKE(b []byte) error {
	out := make([]byte, nonESPMarkerLen+len(b))
	copy(out[nonESPMarkerLen:], b)
	_, err := m.conn.WriteToUDP(out, m.remoteAddr())
	return err
}

// SendESP queues one raw ESP packet, always UDP-encapsulated (bare, no
// marker — its nonzero SPI disambiguates it from the marker on receive),
// for a batched write by sendESPLoop. Safe for concurrent callers (e.g.
// netstack.Mesh's per-flow outbound workers all sending through the same
// peer): it's just a channel send.
func (m *Mux) SendESP(b []byte) error {
	select {
	case m.espOut <- b:
		return nil
	case <-m.done:
		return m.doneError()
	}
}

// sendESPLoop batches whatever's currently queued into as few sendmmsg(2)
// calls (via WriteBatch) as possible — the same non-blocking-drain
// pattern as netstack.Mesh's inboundLoop: a lone packet with nothing
// queued behind it still goes out immediately, batching only kicks in
// under real load.
func (m *Mux) sendESPLoop() {
	addr := m.remoteAddr()
	msgs := make([]ipv4.Message, 0, espSendBatch)
	for {
		select {
		case <-m.done:
			return
		case b := <-m.espOut:
			msgs = append(msgs, ipv4.Message{Buffers: [][]byte{b}, Addr: addr})
		}
	drain:
		for len(msgs) < espSendBatch {
			select {
			case b := <-m.espOut:
				msgs = append(msgs, ipv4.Message{Buffers: [][]byte{b}, Addr: addr})
			default:
				break drain
			}
		}
		if n, err := m.batch.WriteBatch(msgs, 0); err != nil {
			log.Printf("transport: batch send: %d/%d packets sent: %v", n, len(msgs), err)
		}
		msgs = msgs[:0]
	}
}

// RecvIKE returns the next decoded (marker-stripped) IKE message.
func (m *Mux) RecvIKE() ([]byte, error) {
	select {
	case b := <-m.ikeCh:
		return b, nil
	case <-m.done:
		return nil, m.doneError()
	}
}

// RecvIKEUntil is like RecvIKE but gives up at deadline. Unlike spawning a
// goroutine per call, this performs a single select directly on the shared
// channel, so a timed-out call never consumes a message meant for the next
// call — nothing is lost, and nothing leaks.
func (m *Mux) RecvIKEUntil(deadline time.Time) ([]byte, error) {
	select {
	case b := <-m.ikeCh:
		return b, nil
	case <-m.done:
		return nil, m.doneError()
	case <-time.After(time.Until(deadline)):
		return nil, errTimeout
	}
}

var errTimeout = fmt.Errorf("transport: receive timeout")

// IsTimeout reports whether err was returned by RecvIKEUntil expiring.
func IsTimeout(err error) bool { return err == errTimeout }

func (m *Mux) doneError() error {
	err, _ := m.doneErr.Load().(error)
	if err == nil {
		err = fmt.Errorf("transport: closed")
	}
	return err
}

// RecvESP returns the next raw ESP packet.
func (m *Mux) RecvESP() ([]byte, error) {
	select {
	case b := <-m.espCh:
		return b, nil
	case <-m.done:
		return nil, m.doneError()
	}
}

// RecvESPUntil is RecvESP with a deadline (see RecvIKEUntil for why this is
// a single select rather than a spawned goroutine).
func (m *Mux) RecvESPUntil(deadline time.Time) ([]byte, error) {
	select {
	case b := <-m.espCh:
		return b, nil
	case <-m.done:
		return nil, m.doneError()
	case <-time.After(time.Until(deadline)):
		return nil, errTimeout
	}
}

func (m *Mux) readLoop() {
	bufs := make([][]byte, readBatchSize)
	msgs := make([]ipv4.Message, readBatchSize)
	for i := range bufs {
		bufs[i] = make([]byte, readBufferSize)
		msgs[i].Buffers = [][]byte{bufs[i]}
	}
	for {
		n, err := m.batch.ReadBatch(msgs, 0)
		if err != nil {
			if m.closed.Load() {
				m.closeDone(fmt.Errorf("transport: closed"))
				return
			}
			m.closeDone(fmt.Errorf("transport: read: %w", err))
			return
		}
		for i := 0; i < n; i++ {
			raw := bufs[i][:msgs[i].N]
			pkt := append([]byte{}, raw...) // bufs[i] is reused by the next ReadBatch call
			if len(pkt) >= nonESPMarkerLen && isZero(pkt[:nonESPMarkerLen]) {
				select {
				case m.ikeCh <- pkt[nonESPMarkerLen:]:
				default:
					log.Printf("transport: ikeCh full, dropping IKE message")
				}
			} else {
				select {
				case m.espCh <- pkt:
				default:
					log.Printf("transport: espCh full, dropping ESP packet")
				}
			}
		}
	}
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func (m *Mux) Close() error {
	m.closed.Store(true)
	return m.conn.Close()
}
