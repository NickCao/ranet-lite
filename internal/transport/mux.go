// Package transport owns the single UDP socket shared by the IKE control
// channel and UDP-encapsulated ESP data, exactly as a NAT-T-floated IKEv2
// session does on the wire (RFC 3948 / RFC 7296 §2.23): once floated to the
// NAT-T port, IKE messages are prefixed with a 4-byte zero "non-ESP marker"
// and ESP packets are sent bare (their SPI, always nonzero, disambiguates
// them from the marker on receive).
package transport

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const nonESPMarkerLen = 4

// Mux is a UDP socket to exactly one peer, demultiplexing inbound packets
// into IKE and ESP streams and handling the initial-port -> NAT-T-port
// float ranet's strongSwan deployments always trigger (they set
// `encap = yes` unconditionally, RFC 7296 §2.23 note in ranet's vici config).
type Mux struct {
	conn       *net.UDPConn
	remoteIP   net.IP
	remotePort int
	nattPort   int
	floated    atomic.Bool

	ikeCh chan []byte
	espCh chan []byte
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
// configured IKE endpoint (e.g. ranet registry port, commonly non-standard
// such as 13000); nattPort is the well-known port (4500) used after floating.
func Dial(localAddr string, remoteIP net.IP, remotePort, nattPort int) (*Mux, error) {
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve local addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("transport: listen: %w", err)
	}
	m := &Mux{
		conn:       conn,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		nattPort:   nattPort,
		ikeCh:      make(chan []byte, 16),
		espCh:      make(chan []byte, 256),
		done:       make(chan struct{}),
	}
	go m.readLoop()
	return m, nil
}

func (m *Mux) LocalAddr() net.Addr { return m.conn.LocalAddr() }

// Float switches all subsequent traffic to the NAT-T port and starts
// prefixing outbound IKE messages with the non-ESP marker, per RFC 7296
// §2.23. ranet always forces UDP encapsulation, so the initiator floats
// unconditionally right after IKE_SA_INIT rather than relying on the
// NAT_DETECTION_* hash comparison to decide.
func (m *Mux) Float() {
	m.remotePort = m.nattPort
	m.floated.Store(true)
}

func (m *Mux) Floated() bool { return m.floated.Load() }

func (m *Mux) remoteAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: m.remoteIP, Port: m.remotePort}
}

// SendIKE writes one IKE message, adding the non-ESP marker if floated.
func (m *Mux) SendIKE(b []byte) error {
	out := b
	if m.floated.Load() {
		out = make([]byte, nonESPMarkerLen+len(b))
		copy(out[nonESPMarkerLen:], b)
	}
	_, err := m.conn.WriteToUDP(out, m.remoteAddr())
	return err
}

// SendESP writes one raw ESP packet. Only valid once floated (ranet always
// forces encapsulation, so ESP is always UDP-encapsulated in this client).
func (m *Mux) SendESP(b []byte) error {
	_, err := m.conn.WriteToUDP(b, m.remoteAddr())
	return err
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
	buf := make([]byte, 65536)
	for {
		n, _, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			if m.closed.Load() {
				m.closeDone(fmt.Errorf("transport: closed"))
				return
			}
			m.closeDone(fmt.Errorf("transport: read: %w", err))
			return
		}
		pkt := append([]byte{}, buf[:n]...)
		switch {
		case n >= nonESPMarkerLen && isZero(pkt[:nonESPMarkerLen]):
			select {
			case m.ikeCh <- pkt[nonESPMarkerLen:]:
			default:
			}
		case !m.floated.Load():
			// Pre-float, IKE messages carry no marker at all.
			select {
			case m.ikeCh <- pkt:
			default:
			}
		default:
			select {
			case m.espCh <- pkt:
			default:
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
