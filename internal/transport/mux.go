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
	espChanSize     = 4096
	espOutBatchSize = 64
)

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
	m := &Mux{hub: h, endpoint: endpoint, ikeCh: make(chan ikeDatagram, 16), espCh: make(chan []byte, espChanSize), espOut: make(chan [][]byte, espOutBatchSize), done: make(chan struct{})}
	h.mu.Lock()
	if h.closed.Load() {
		h.mu.Unlock()
		return nil, fmt.Errorf("transport: hub closed")
	}
	h.muxes[m] = struct{}{}
	h.mu.Unlock()
	go m.sendESPLoop()
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
		for i := 0; i < n; i++ {
			raw := bufs[i][:sizes[i]]
			if len(raw) < nonESPMarkerLen {
				continue
			}
			var m *Mux
			var pkt []byte
			h.mu.Lock()
			if raw[0]|raw[1]|raw[2]|raw[3] == 0 {
				if len(raw) >= nonESPMarkerLen+8 {
					spi := uint64(raw[4])<<56 | uint64(raw[5])<<48 | uint64(raw[6])<<40 | uint64(raw[7])<<32 | uint64(raw[8])<<24 | uint64(raw[9])<<16 | uint64(raw[10])<<8 | uint64(raw[11])
					m, pkt = h.ike[spi], append([]byte(nil), raw[nonESPMarkerLen:]...)
				}
			} else {
				spi := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
				m, pkt = h.esp[spi], append([]byte(nil), raw...)
			}
			h.mu.Unlock()
			if m == nil {
				continue
			}
			if len(pkt) >= nonESPMarkerLen && raw[0]|raw[1]|raw[2]|raw[3] == 0 {
				select {
				case m.ikeCh <- ikeDatagram{raw: pkt, endpoint: eps[i]}:
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

// Mux is one peer's logical IKE and ESP channel on a Hub.
type Mux struct {
	hub        *Hub
	endpointMu sync.RWMutex
	endpoint   conn.Endpoint
	ikeCh      chan ikeDatagram
	espCh      chan []byte
	espOut     chan [][]byte
	done       chan struct{}
	doneOnce   sync.Once
	doneErr    atomic.Value
	closed     atomic.Bool
	ownHub     bool
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

func (m *Mux) sendESPLoop() {
	bufs := make([][]byte, 0, espSendBatch)
	var packed []byte
	var pendingBatch [][]byte
	for {
	drain:
		for len(bufs) < espSendBatch {
			if len(pendingBatch) == 0 {
				if len(bufs) == 0 {
					select {
					case <-m.done:
						return
					case pendingBatch = <-m.espOut:
					}
				} else {
					select {
					case pendingBatch = <-m.espOut:
					default:
						break drain
					}
				}
			}
			n := min(espSendBatch-len(bufs), len(pendingBatch))
			bufs = append(bufs, pendingBatch[:n]...)
			pendingBatch = pendingBatch[n:]
		}
		if len(bufs) > 1 {
			packed = packForGSO(packed, bufs)
		}
		if err := m.hub.bind.Send(bufs, m.currentEndpoint()); err != nil {
			log.Printf("transport: batch send of %d packets: %v", len(bufs), err)
		}
		bufs = bufs[:0]
	}
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
	select {
	case b := <-m.espCh:
		return b, nil
	case <-m.done:
		return nil, m.doneError()
	}
}

// RecvESPBatch blocks for one ESP packet, then drains immediately available
// packets into dst up to its capacity. A nil dst gets the transport's normal
// batch capacity. Keeping the receive batch intact lets callers amortize
// decrypt-pipeline and TUN write overhead without delaying a lone packet.
func (m *Mux) RecvESPBatch(dst [][]byte) ([][]byte, error) {
	if cap(dst) == 0 {
		dst = make([][]byte, 0, espSendBatch)
	} else {
		dst = dst[:0]
	}
	select {
	case b := <-m.espCh:
		dst = append(dst, b)
	case <-m.done:
		return nil, m.doneError()
	}
	for len(dst) < cap(dst) {
		select {
		case b := <-m.espCh:
			dst = append(dst, b)
		case <-m.done:
			return dst, nil
		default:
			return dst, nil
		}
	}
	return dst, nil
}

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
