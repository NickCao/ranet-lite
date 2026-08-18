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
	espSendBatch    = 128
	espChanSize     = 4096
	espOutBatchSize = 64
)

// Mux is a UDP socket to one peer, demultiplexing inbound packets into IKE
// and ESP streams. wireguard-go's conn.Bind provides socket buffers, batched
// syscalls, and UDP GSO/GRO.
type Mux struct {
	bind     conn.Bind
	endpoint conn.Endpoint
	port     uint16

	ikeCh  chan []byte
	espCh  chan []byte
	espOut chan [][]byte // queued outbound ESP batches; ownership transfers to sendESPLoop

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
		espOut:   make(chan [][]byte, espOutBatchSize),
		done:     make(chan struct{}),
	}
	for _, fn := range fns {
		go m.receiveLoop(fn)
	}
	go m.sendESPLoop()
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

// SendESP queues one raw ESP packet for callers that do not already have a
// batch. Data-plane traffic normally uses SendESPBatch.
func (m *Mux) SendESP(b []byte) error {
	return m.SendESPBatch([][]byte{b})
}

// SendESPBatch transfers ownership of a packet batch to the send loop. The
// caller must not mutate the slice or its packets after this method returns.
func (m *Mux) SendESPBatch(bufs [][]byte) error {
	if len(bufs) == 0 {
		return nil
	}
	select {
	case m.espOut <- bufs:
		return nil
	case <-m.done:
		return m.doneError()
	}
}

// sendESPLoop batches whatever's currently queued into as few Bind.Send
// calls as possible (each of which UDP-GSO-coalesces its buffers into as
// few underlying datagrams as the kernel supports) — a non-blocking-drain
// pattern: a lone packet with nothing queued behind it still goes out
// immediately, batching only kicks in under real load.
func (m *Mux) sendESPLoop() {
	bufs := make([][]byte, 0, espSendBatch)
	var packed []byte
	var pending [][]byte
	for {
	drain:
		for len(bufs) < espSendBatch {
			if len(pending) == 0 {
				if len(bufs) == 0 {
					select {
					case <-m.done:
						return
					case pending = <-m.espOut:
					}
				} else {
					select {
					case pending = <-m.espOut:
					default:
						break drain
					}
					if len(pending) == 0 {
						break drain
					}
				}
			}
			n := min(espSendBatch-len(bufs), len(pending))
			bufs = append(bufs, pending[:n]...)
			pending = pending[n:]
		}
		if len(bufs) > 1 {
			packed = packForGSO(packed, bufs)
		}
		if err := m.bind.Send(bufs, m.endpoint); err != nil {
			log.Printf("transport: batch send of %d packets: %v", len(bufs), err)
		}
		bufs = bufs[:0]
	}
}

// packForGSO copies a send batch into one contiguous allocation. Each packet's
// slice retains capacity through the end of that allocation, which lets
// wireguard-go's Bind append following packets to a GSO base packet in place.
// The destination is reused after the synchronous Bind.Send call returns.
func packForGSO(dst []byte, bufs [][]byte) []byte {
	total := 0
	for _, buf := range bufs {
		total += len(buf)
	}
	if cap(dst) < total {
		dst = make([]byte, 0, total)
	} else {
		dst = dst[:0]
	}
	for i, buf := range bufs {
		start := len(dst)
		dst = append(dst, buf...)
		bufs[i] = dst[start:len(dst)]
	}
	return dst
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
			if len(pkt) >= nonESPMarkerLen && pkt[0]|pkt[1]|pkt[2]|pkt[3] == 0 {
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

func (m *Mux) Close() error {
	m.closed.Store(true)
	return m.bind.Close()
}
