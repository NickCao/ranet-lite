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
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

const nonESPMarkerLen = 4

// readBufferSize is the per-slot buffer size handed to conn.Bind's receive
// funcs. UDP GRO coalesces several inbound datagrams into one underlying
// read internally, but the Bind splits that back into one full datagram per
// slot before we ever see it -- this only needs to hold one datagram.
const readBufferSize = 65536

// espSendBatch bounds how many queued ESP packets sendESPLoop batches into
// one Bind.Send call, and espChanSize is deliberately generous: it's the
// buffer absorbing any gap between how fast the receive loop can receive
// and how fast the consumer can decrypt+deliver (see cmd/ranet-lite's
// parallel inbound worker pool) -- too small and a burst overflows it,
// which is real, permanent packet loss, not just added latency.
const (
	espSendBatch = 128
	espChanSize  = 4096
)

// sendShards is the number of independent (channel, goroutine) pairs
// SendESP's outbound traffic is split across, indexed by the caller's
// shard argument. This uses the exact formula netstack.outboundWorkers
// does (both derived from the same live runtime.NumCPU()), so a flow's
// encrypt worker and its send-syscall goroutine end up as the same shard
// end-to-end without the two packages needing to coordinate explicitly --
// without this, every flow's encrypted packets funnel back into one send
// goroutine regardless of how many encrypt workers ran them, capping a
// multi-stream transfer's syscall-heavy work to a single core no matter
// how many flows there are. SendESP indexes shards mod len(), so an exact
// match isn't required for correctness, just for the two packages' worker
// counts to line up for maximum parallelism.
var sendShards = min(runtime.NumCPU(), 16)

// Mux is a UDP socket to exactly one peer, demultiplexing inbound packets
// into IKE and ESP streams. It's built on wireguard-go's conn.Bind (the
// same package used for the mesh's tun device) rather than a hand-rolled
// socket: StdNetBind already does everything a hand-rolled implementation
// would have to reinvent for this workload -- batched sendmmsg/recvmmsg,
// forcing the kernel receive buffer past its default via SO_RCVBUFFORCE
// (the exact fix for a real, confirmed packet-loss bug this package used
// to carry by hand), and, the actual reason to prefer it, real UDP GSO/GRO:
// letting the kernel carry many ESP datagrams through its networking stack
// as one segmented unit instead of iterating the stack once per datagram
// even inside a batched syscall. See
// https://tailscale.com/blog/more-throughput for why that distinction
// matters -- sendmmsg/recvmmsg batching alone tops out well short of what
// UDP GSO/GRO reaches on the same hardware.
type Mux struct {
	bind     conn.Bind
	endpoint conn.Endpoint
	port     uint16

	ikeCh  chan []byte
	espCh  chan []byte
	espOut []chan []byte // sendShards queues of outbound ESP packets awaiting a batched Send, indexed by SendESP's shard argument

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

	gaps seqGapTracker // temporary diagnostic, see seqGapTracker's doc comment
}

// seqGapTracker is a temporary diagnostic for locating real, direction-
// specific packet loss that survived every other instrumented check
// (channel overflows, kernel UDP/tun/backlog drops, replay window, GC,
// delivery reordering): does every packet the sender transmits actually
// reach this socket at all. ESP's sequence number is sent in the clear
// (RFC 4303 -- only the SPI and sequence number are unencrypted), strictly
// incrementing per packet, so gaps in it observed here -- at the earliest,
// single-threaded point after the read syscall, before any concurrent
// processing -- prove real loss between the sender and this socket.
//
// A sequence jump alone proves nothing by itself: the skipped numbers may
// simply be in flight and arrive slightly later (real reordering, not
// loss), so a gap is only reported once it's stayed open long enough that
// a late arrival is implausible (lossLogAfter, generously beyond any real
// RTT on a local link) rather than on the first jump.
type seqGapTracker struct {
	mu      sync.Mutex
	seen    map[uint32]bool // per-SPI: has any packet been seen yet
	highest map[uint32]uint32
	pending map[uint32]map[uint32]time.Time // per-SPI: seq -> when the gap opened
}

const lossLogAfter = 200 * time.Millisecond

// maxTrackedGap bounds how large a sequence jump this will track
// individually — well beyond any real burst of loss expected on a
// functioning link, but small enough to never turn a single packet into
// an unbounded amount of map-filling work.
const maxTrackedGap = 8192

func (g *seqGapTracker) observe(spi, seq uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = make(map[uint32]bool)
		g.highest = make(map[uint32]uint32)
		g.pending = make(map[uint32]map[uint32]time.Time)
	}
	if !g.seen[spi] {
		g.seen[spi] = true
		g.highest[spi] = seq
		return
	}
	pending := g.pending[spi]
	if _, ok := pending[seq]; ok {
		delete(pending, seq) // arrived late: reordering, not loss
	} else if gap := seq - g.highest[spi] - 1; seq > g.highest[spi]+1 && gap <= maxTrackedGap {
		// A jump this large is either a fresh/reset SA (nothing to
		// compare against) or too big to mean anything useful here; only
		// track individually-sized gaps worth suspecting as real loss.
		if pending == nil {
			pending = make(map[uint32]time.Time)
			g.pending[spi] = pending
		}
		now := time.Now()
		for s := g.highest[spi] + 1; s < seq; s++ {
			pending[s] = now
		}
	}
	if seq > g.highest[spi] {
		g.highest[spi] = seq
	}
	now := time.Now()
	for s, t := range pending {
		if now.Sub(t) > lossLogAfter {
			log.Printf("transport: SPI %08x seq %d never arrived at the socket (%s elapsed, %d packets ahead) — confirmed lost, not reordering", spi, s, lossLogAfter, g.highest[spi]-s)
			delete(pending, s)
		}
	}
}

// closeDone wakes every blocked Recv* call exactly once, regardless of
// whether it's triggered by a real read error or an explicit Close().
func (m *Mux) closeDone(err error) {
	m.doneOnce.Do(func() {
		m.doneErr.Store(err)
		close(m.done)
	})
}

// Dial opens the shared socket. localAddr may be "" (or ":0") to let the OS
// pick an ephemeral port on all interfaces. Only the port portion of
// localAddr is honored -- conn.Bind (see Mux's doc comment for why this
// package uses it) always binds every interface, so a specific local IP
// can't be requested; ranet-lite's production path never asks for one
// (PeerConfig.LocalAddr is always left unset), only a couple of standalone
// debug commands under cmd/ do, and they still work, just without pinning
// to a specific interface. remoteAddr:remotePort is the peer's configured
// IKE endpoint — ranet's registry port, commonly non-standard (e.g. 13000)
// — and is the only port ever used; there is no separate NAT-T port and no
// floating.
func Dial(localAddr string, remoteIP net.IP, remotePort int) (*Mux, error) {
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve local addr: %w", err)
	}
	if laddr.IP != nil && !laddr.IP.IsUnspecified() {
		log.Printf("transport: binding to a specific local address (%s) isn't supported by this package's underlying conn.Bind; binding all interfaces on port %d instead", laddr.IP, laddr.Port)
	}

	bind := conn.NewStdNetBind()
	fns, actualPort, err := bind.Open(uint16(laddr.Port))
	if err != nil {
		return nil, fmt.Errorf("transport: open bind: %w", err)
	}

	endpoint, err := bind.ParseEndpoint(net.JoinHostPort(remoteIP.String(), strconv.Itoa(remotePort)))
	if err != nil {
		bind.Close()
		return nil, fmt.Errorf("transport: parse remote endpoint: %w", err)
	}

	m := &Mux{
		bind:     bind,
		endpoint: endpoint,
		port:     actualPort,
		ikeCh:    make(chan []byte, 16),
		espCh:    make(chan []byte, espChanSize),
		espOut:   make([]chan []byte, sendShards),
		done:     make(chan struct{}),
	}
	for _, fn := range fns {
		go m.receiveLoop(fn)
	}
	for i := range m.espOut {
		m.espOut[i] = make(chan []byte, espChanSize)
		go m.sendESPLoop(m.espOut[i])
	}
	return m, nil
}

// LocalAddr's IP is always unspecified -- see Dial's doc comment; only the
// port is meaningful.
func (m *Mux) LocalAddr() net.Addr { return &net.UDPAddr{Port: int(m.port)} }

// SendIKE writes one IKE message, always prefixed with the non-ESP marker
// — ranet forces UDP encapsulation unconditionally, so even the very first
// IKE_SA_INIT request must carry it; the responder isn't listening for a
// bare (unmarked) ISAKMP header on this port at all.
func (m *Mux) SendIKE(b []byte) error {
	out := make([]byte, nonESPMarkerLen+len(b))
	copy(out[nonESPMarkerLen:], b)
	return m.bind.Send([][]byte{out}, m.endpoint)
}

// SendESP queues one raw ESP packet, always UDP-encapsulated (bare, no
// marker — its nonzero SPI disambiguates it from the marker on receive),
// for a batched Send by one of sendShards sendESPLoop goroutines. shard
// selects which one -- callers with a flow to be consistent about (e.g.
// netstack.Mesh's per-flow outbound workers) should pass the same shard
// index every time for a given flow, so that flow's packets stay in
// relative order through the batching below; callers without one (e.g.
// babel control traffic via Peer.SendRaw) can pass any fixed value. Safe
// for concurrent callers on different shards: each is just a channel send.
func (m *Mux) SendESP(shard int, b []byte) error {
	ch := m.espOut[shard%len(m.espOut)]
	select {
	case ch <- b:
		return nil
	case <-m.done:
		return m.doneError()
	}
}

// sendESPLoop batches whatever's currently queued on ch into as few
// Bind.Send calls as possible (each of which UDP-GSO-coalesces its buffers
// into as few underlying datagrams as the kernel supports) — a
// non-blocking-drain pattern: a lone packet with nothing queued behind it
// still goes out immediately, batching only kicks in under real load.
// sendShards of these run concurrently, one per shard, so that
// syscall-heavy send work spreads across cores the same way encryption
// already does upstream in netstack.Mesh.outboundLoop.
func (m *Mux) sendESPLoop(ch chan []byte) {
	bufs := make([][]byte, 0, espSendBatch)
	for {
		select {
		case <-m.done:
			return
		case b := <-ch:
			bufs = append(bufs, b)
		}
	drain:
		for len(bufs) < espSendBatch {
			select {
			case b := <-ch:
				bufs = append(bufs, b)
			default:
				break drain
			}
		}
		if err := m.bind.Send(bufs, m.endpoint); err != nil {
			log.Printf("transport: batch send of %d packets: %v", len(bufs), err)
		}
		bufs = bufs[:0]
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

// receiveLoop runs one of Bind.Open's ReceiveFuncs (IPv4 and IPv6 each get
// their own) until it errors, demuxing every datagram it hands back into
// the IKE or ESP channel. UDP GRO coalescing/splitting is handled entirely
// inside the Bind -- fn always hands back one full datagram per slot, so
// this sees exactly what a plain recvmmsg loop would.
func (m *Mux) receiveLoop(fn conn.ReceiveFunc) {
	batch := m.bind.BatchSize()
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	eps := make([]conn.Endpoint, batch)
	for i := range bufs {
		bufs[i] = make([]byte, readBufferSize)
	}
	for {
		n, err := fn(bufs, sizes, eps)
		if err != nil {
			if m.closed.Load() {
				m.closeDone(fmt.Errorf("transport: closed"))
				return
			}
			m.closeDone(fmt.Errorf("transport: read: %w", err))
			return
		}
		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			raw := bufs[i][:sizes[i]]
			pkt := append([]byte{}, raw...) // bufs[i] is reused by the next call
			if len(pkt) >= nonESPMarkerLen && isZero(pkt[:nonESPMarkerLen]) {
				select {
				case m.ikeCh <- pkt[nonESPMarkerLen:]:
				default:
					log.Printf("transport: ikeCh full, dropping IKE message")
				}
			} else {
				if len(pkt) >= 8 {
					m.gaps.observe(binary.BigEndian.Uint32(pkt[0:4]), binary.BigEndian.Uint32(pkt[4:8]))
				}
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
	return m.bind.Close()
}
