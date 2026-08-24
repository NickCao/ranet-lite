// Package transport shares one UDP socket between IKE control messages and
// UDP-encapsulated ESP packets. IKE packets carry a four-byte non-ESP marker;
// ESP packets are bare and begin with their nonzero inbound SPI.
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

const (
	nonESPMarkerLen = 4
	readBufferSize  = 65536
	espSendBatch    = 128
	// espChanSize absorbs receive bursts before a peer's workers can drain
	// them. Some backends return only one or two datagrams per kernel batch,
	// so this remains sized by observed burst count even though each channel
	// element now carries a whole batch.
	espChanSize = 4096
)

var espPackedPool = sync.Pool{New: func() any { return new([]byte) }}

// Hub owns one local UDP port and routes incoming packets to registered Muxes.
type Hub struct {
	bind conn.Bind
	port uint16

	mu        sync.Mutex
	ike       map[uint64]*Mux
	esp       map[uint32]*Mux
	muxes     map[*Mux]struct{}
	closed    atomic.Bool
	closeOnce sync.Once
}

// Endpoint is the authenticated datagram source retained by IKE so replies
// can follow a peer whose NAT mapping changed.
type Endpoint = conn.Endpoint

type ikeDatagram struct {
	raw      []byte
	endpoint Endpoint
}

type espDatagramBatch struct {
	ticket  uint64
	packets [][]byte
}

// NewHub binds localAddr. A specific IP is not supported by conn.Bind, so only
// its port is used.
func NewHub(localAddr string) (*Hub, error) {
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve local addr: %w", err)
	}
	if laddr.IP != nil && !laddr.IP.IsUnspecified() {
		log.Printf("transport: binding to a specific local address (%s) isn't supported; binding all interfaces on port %d instead", laddr.IP, laddr.Port)
	}
	bind := conn.NewStdNetBind()
	fns, port, err := bind.Open(uint16(laddr.Port))
	if err != nil {
		return nil, fmt.Errorf("transport: open bind: %w", err)
	}
	h := &Hub{bind: bind, port: port, ike: make(map[uint64]*Mux), esp: make(map[uint32]*Mux), muxes: make(map[*Mux]struct{})}
	for _, fn := range fns {
		go h.receiveLoop(fn)
	}
	return h, nil
}

// NewMux creates a logical peer channel on this hub.
func (h *Hub) NewMux(remoteIP net.IP, remotePort int) (*Mux, error) {
	endpoint, err := h.bind.ParseEndpoint(net.JoinHostPort(remoteIP.String(), strconv.Itoa(remotePort)))
	if err != nil {
		return nil, fmt.Errorf("transport: parse remote endpoint: %w", err)
	}
	m := &Mux{hub: h, endpoint: endpoint, ikeCh: make(chan ikeDatagram, 16), espCh: make(chan espDatagramBatch, espChanSize), done: make(chan struct{})}
	h.mu.Lock()
	if h.closed.Load() {
		h.mu.Unlock()
		return nil, fmt.Errorf("transport: hub closed")
	}
	h.muxes[m] = struct{}{}
	h.mu.Unlock()
	return m, nil
}

// LocalAddr returns the hub's wildcard local address; only its port is useful.
func (h *Hub) LocalAddr() net.Addr { return &net.UDPAddr{Port: int(h.port)} }

// Close closes the socket and every mux using it.
func (h *Hub) Close() error {
	return h.fail(fmt.Errorf("transport: closed"))
}

func (h *Hub) fail(cause error) (bindErr error) {
	h.closeOnce.Do(func() {
		h.closed.Store(true)
		bindErr = h.bind.Close()
		h.mu.Lock()
		muxes := make([]*Mux, 0, len(h.muxes))
		for m := range h.muxes {
			muxes = append(muxes, m)
		}
		h.ike = make(map[uint64]*Mux)
		h.esp = make(map[uint32]*Mux)
		h.muxes = make(map[*Mux]struct{})
		h.mu.Unlock()
		for _, m := range muxes {
			m.closed.Store(true)
			m.closeDone(cause)
		}
	})
	return bindErr
}

func (h *Hub) receiveLoop(fn conn.ReceiveFunc) {
	batch := h.bind.BatchSize()
	bufs, sizes, eps := make([][]byte, batch), make([]int, batch), make([]conn.Endpoint, batch)
	for i := range bufs {
		bufs[i] = make([]byte, readBufferSize)
	}
	type pendingIKE struct {
		mux      *Mux
		datagram ikeDatagram
	}
	espBatches := make(map[*Mux][][]byte)
	ikeDatagrams := make([]pendingIKE, 0, batch)
	for {
		n, err := fn(bufs, sizes, eps)
		if err != nil {
			if h.closed.Load() {
				h.fail(fmt.Errorf("transport: closed"))
			} else {
				h.fail(fmt.Errorf("transport: read: %w", err))
			}
			return
		}
		clear(espBatches)
		ikeDatagrams = ikeDatagrams[:0]
		h.mu.Lock()
		for i := 0; i < n; i++ {
			raw := bufs[i][:sizes[i]]
			if len(raw) < nonESPMarkerLen {
				continue
			}
			if raw[0]|raw[1]|raw[2]|raw[3] == 0 {
				if len(raw) >= nonESPMarkerLen+8 {
					spi := uint64(raw[4])<<56 | uint64(raw[5])<<48 | uint64(raw[6])<<40 | uint64(raw[7])<<32 | uint64(raw[8])<<24 | uint64(raw[9])<<16 | uint64(raw[10])<<8 | uint64(raw[11])
					if m := h.ike[spi]; m != nil {
						ikeDatagrams = append(ikeDatagrams, pendingIKE{
							mux: m,
							datagram: ikeDatagram{
								raw:      append([]byte(nil), raw[nonESPMarkerLen:]...),
								endpoint: eps[i],
							},
						})
					}
				}
			} else {
				spi := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
				if m := h.esp[spi]; m != nil {
					// Keep views into the receive buffers only until this socket
					// batch has been demultiplexed. packReceivedBatch below moves
					// all packets for a peer into one allocation before fn is
					// allowed to reuse the buffers.
					espBatches[m] = append(espBatches[m], raw)
				}
			}
		}
		h.mu.Unlock()
		for _, pending := range ikeDatagrams {
			select {
			case pending.mux.ikeCh <- pending.datagram:
			default:
				log.Printf("transport: ikeCh full, dropping IKE message")
			}
		}
		for m, packets := range espBatches {
			packets = packReceivedBatch(packets)
			if !m.dispatchESP(packets) {
				log.Printf("transport: espCh full, dropping %d ESP packets", len(packets))
			}
		}
	}
}

// packReceivedBatch detaches packets from receiveLoop's reusable recvmmsg
// buffers with one allocation per peer and socket read, rather than one heap
// allocation per datagram. Packet slice boundaries are retained so parallel
// ESP workers can authenticate the batch without any further framing work.
func packReceivedBatch(packets [][]byte) [][]byte {
	total := 0
	for _, packet := range packets {
		total += len(packet)
	}
	storage := make([]byte, total)
	offset := 0
	for i, packet := range packets {
		n := copy(storage[offset:], packet)
		packets[i] = storage[offset : offset+n]
		offset += n
	}
	return packets
}

// Mux is one peer's logical IKE and ESP channel on a Hub.
type Mux struct {
	hub           *Hub
	endpointMu    sync.RWMutex
	endpoint      conn.Endpoint
	ikeCh         chan ikeDatagram
	espRecvMu     sync.Mutex
	espDispatchMu sync.Mutex
	espTicket     uint64
	espCh         chan espDatagramBatch
	espPending    [][]byte
	done          chan struct{}
	doneOnce      sync.Once
	doneErr       atomic.Value
	closed        atomic.Bool
	ownHub        bool
}

// dispatchESP assigns a receive-order ticket at the socket demultiplexer.
// Both the ticket and channel insertion happen under one lock because a Hub
// may have separate IPv4 and IPv6 receive loops. A dropped batch does not
// consume a ticket, so the ordered decrypt emitter can never wait forever on
// a hole caused by backpressure.
func (m *Mux) dispatchESP(packets [][]byte) bool {
	m.espDispatchMu.Lock()
	defer m.espDispatchMu.Unlock()
	batch := espDatagramBatch{ticket: m.espTicket, packets: packets}
	select {
	case m.espCh <- batch:
		m.espTicket++
		return true
	default:
		return false
	}
}

// Dial preserves the one-peer convenience path. The returned mux owns its
// newly-created hub and closes it when closed.
func Dial(localAddr string, remoteIP net.IP, remotePort int) (*Mux, error) {
	h, err := NewHub(localAddr)
	if err != nil {
		return nil, err
	}
	m, err := h.NewMux(remoteIP, remotePort)
	if err != nil {
		_ = h.Close()
		return nil, err
	}
	m.ownHub = true
	return m, nil
}

func (m *Mux) LocalAddr() net.Addr { return m.hub.LocalAddr() }
func (m *Mux) IsClosed() bool      { return m.closed.Load() || m.hub.closed.Load() }

// RegisterIKE routes packets whose marked IKE header has spi as SPIi to m.
func (m *Mux) RegisterIKE(spi uint64) error { return m.registerIKE(spi) }
func (m *Mux) registerIKE(spi uint64) error {
	m.hub.mu.Lock()
	defer m.hub.mu.Unlock()
	if m.closed.Load() || m.hub.closed.Load() {
		return fmt.Errorf("transport: closed")
	}
	if owner := m.hub.ike[spi]; owner != nil && owner != m {
		return fmt.Errorf("transport: IKE SPI %016x already registered", spi)
	}
	m.hub.ike[spi] = m
	return nil
}

// UnregisterIKE stops routing IKE packets for spi to m.
func (m *Mux) UnregisterIKE(spi uint64) {
	m.hub.mu.Lock()
	if m.hub.ike[spi] == m {
		delete(m.hub.ike, spi)
	}
	m.hub.mu.Unlock()
}

// RegisterESP routes bare ESP packets whose inbound SPI is spi to m.
func (m *Mux) RegisterESP(spi uint32) error {
	if spi == 0 {
		return fmt.Errorf("transport: ESP SPI must be nonzero")
	}
	m.hub.mu.Lock()
	defer m.hub.mu.Unlock()
	if m.closed.Load() || m.hub.closed.Load() {
		return fmt.Errorf("transport: closed")
	}
	if owner := m.hub.esp[spi]; owner != nil && owner != m {
		return fmt.Errorf("transport: ESP SPI %08x already registered", spi)
	}
	m.hub.esp[spi] = m
	return nil
}

// UnregisterESP stops routing ESP packets for spi to m.
func (m *Mux) UnregisterESP(spi uint32) {
	m.hub.mu.Lock()
	if m.hub.esp[spi] == m {
		delete(m.hub.esp, spi)
	}
	m.hub.mu.Unlock()
}

func (m *Mux) SendIKE(b []byte) error {
	return m.SendIKETo(b, m.currentEndpoint())
}

func (m *Mux) currentEndpoint() Endpoint {
	m.endpointMu.RLock()
	defer m.endpointMu.RUnlock()
	return m.endpoint
}

// AdoptEndpoint changes the destination used for subsequent IKE and ESP
// traffic. IKE calls this only after authenticating a request from endpoint.
func (m *Mux) AdoptEndpoint(endpoint Endpoint) {
	m.endpointMu.Lock()
	m.endpoint = endpoint
	m.endpointMu.Unlock()
}

func (m *Mux) SendIKETo(b []byte, endpoint Endpoint) error {
	out := make([]byte, nonESPMarkerLen+len(b))
	copy(out[nonESPMarkerLen:], b)
	return m.hub.bind.Send([][]byte{out}, endpoint)
}
func (m *Mux) SendESP(b []byte) error { return m.SendESPBatch([][]byte{b}) }

// SendESPBatch writes directly to the shared UDP bind. The calling data-plane
// worker retains ownership all the way through sendmmsg/UDP GSO, avoiding a
// channel handoff and making completion the peer's ordered-send boundary.
func (m *Mux) SendESPBatch(bufs [][]byte) error {
	if len(bufs) == 0 {
		return nil
	}
	select {
	case <-m.done:
		return m.doneError()
	default:
	}

	packedPtr := espPackedPool.Get().(*[]byte)
	packed := (*packedPtr)[:0]
	defer func() {
		*packedPtr = packed[:0]
		espPackedPool.Put(packedPtr)
	}()
	endpoint := m.currentEndpoint()
	var storage [espSendBatch][]byte
	for len(bufs) != 0 {
		n := min(len(bufs), len(storage))
		batch := storage[:n]
		copy(batch, bufs[:n])
		if n > 1 {
			packed = packForGSO(packed, batch)
		}
		if err := m.hub.bind.Send(batch, endpoint); err != nil {
			return fmt.Errorf("transport: send ESP batch: %w", err)
		}
		bufs = bufs[n:]
	}
	return nil
}

func packForGSO(dst []byte, bufs [][]byte) []byte {
	total := 0
	for _, b := range bufs {
		total += len(b)
	}
	if cap(dst) < total {
		dst = make([]byte, 0, total)
	} else {
		dst = dst[:0]
	}
	for i, b := range bufs {
		start := len(dst)
		dst = append(dst, b...)
		bufs[i] = dst[start:len(dst)]
	}
	return dst
}

func (m *Mux) RecvIKE() ([]byte, error) {
	b, _, err := m.RecvIKEFrom()
	return b, err
}
func (m *Mux) RecvIKEFrom() ([]byte, Endpoint, error) {
	select {
	case d := <-m.ikeCh:
		return d.raw, d.endpoint, nil
	case <-m.done:
		return nil, nil, m.doneError()
	}
}
func (m *Mux) RecvIKEUntil(deadline time.Time) ([]byte, error) {
	b, _, err := m.RecvIKEFromUntil(deadline)
	return b, err
}
func (m *Mux) RecvIKEFromUntil(deadline time.Time) ([]byte, Endpoint, error) {
	select {
	case d := <-m.ikeCh:
		return d.raw, d.endpoint, nil
	case <-m.done:
		return nil, nil, m.doneError()
	case <-time.After(time.Until(deadline)):
		return nil, nil, errTimeout
	}
}
func (m *Mux) RecvESP() ([]byte, error) {
	m.espRecvMu.Lock()
	defer m.espRecvMu.Unlock()
	if len(m.espPending) == 0 {
		select {
		case batch := <-m.espCh:
			m.espPending = batch.packets
		case <-m.done:
			return nil, m.doneError()
		}
	}
	b := m.espPending[0]
	m.espPending = m.espPending[1:]
	return b, nil
}

// RecvESPBatchConcurrent returns one complete socket-demultiplexed batch and
// its receive-order ticket. It is safe for multiple data-plane workers to call
// concurrently: the transport channel distributes batches, while the ticket
// lets their independently decrypted results be emitted in original order.
// It must not be mixed with RecvESP, RecvESPBatch, or RecvESPUntil on one Mux.
func (m *Mux) RecvESPBatchConcurrent() (uint64, [][]byte, error) {
	select {
	case batch := <-m.espCh:
		return batch.ticket, batch.packets, nil
	case <-m.done:
		return 0, nil, m.doneError()
	}
}

// RecvESPBatch blocks for one ESP packet, then drains immediately available
// packets into dst up to its capacity. A nil dst gets the transport's normal
// batch capacity. Keeping the receive batch intact lets callers amortize
// decrypt-pipeline and TUN write overhead without delaying a lone packet.
func (m *Mux) RecvESPBatch(dst [][]byte) ([][]byte, error) {
	m.espRecvMu.Lock()
	defer m.espRecvMu.Unlock()
	if cap(dst) == 0 {
		dst = make([][]byte, 0, espSendBatch)
	} else {
		dst = dst[:0]
	}
	for len(dst) < cap(dst) {
		if len(m.espPending) == 0 {
			if len(dst) == 0 {
				select {
				case batch := <-m.espCh:
					m.espPending = batch.packets
				case <-m.done:
					return nil, m.doneError()
				}
			} else {
				select {
				case batch := <-m.espCh:
					m.espPending = batch.packets
				case <-m.done:
					return dst, nil
				default:
					return dst, nil
				}
			}
		}
		n := min(cap(dst)-len(dst), len(m.espPending))
		dst = append(dst, m.espPending[:n]...)
		m.espPending = m.espPending[n:]
	}
	return dst, nil
}

func (m *Mux) RecvESPUntil(deadline time.Time) ([]byte, error) {
	m.espRecvMu.Lock()
	defer m.espRecvMu.Unlock()
	if len(m.espPending) == 0 {
		select {
		case batch := <-m.espCh:
			m.espPending = batch.packets
		case <-m.done:
			return nil, m.doneError()
		case <-time.After(time.Until(deadline)):
			return nil, errTimeout
		}
	}
	b := m.espPending[0]
	m.espPending = m.espPending[1:]
	return b, nil
}

var errTimeout = fmt.Errorf("transport: receive timeout")

func IsTimeout(err error) bool     { return err == errTimeout }
func (m *Mux) closeDone(err error) { m.doneOnce.Do(func() { m.doneErr.Store(err); close(m.done) }) }
func (m *Mux) doneError() error {
	if err, _ := m.doneErr.Load().(error); err != nil {
		return err
	}
	return fmt.Errorf("transport: closed")
}

// Close unregisters this peer. It does not close the shared hub.
func (m *Mux) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	m.hub.mu.Lock()
	for spi, owner := range m.hub.ike {
		if owner == m {
			delete(m.hub.ike, spi)
		}
	}
	for spi, owner := range m.hub.esp {
		if owner == m {
			delete(m.hub.esp, spi)
		}
	}
	delete(m.hub.muxes, m)
	m.hub.mu.Unlock()
	m.closeDone(fmt.Errorf("transport: closed"))
	if m.ownHub {
		return m.hub.Close()
	}
	return nil
}
