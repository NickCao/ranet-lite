package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// listenPeer opens a plain UDP socket standing in for "the peer" at the
// far end of a Mux, on the given loopback address (v4 or v6) — used to
// verify what a Mux actually puts on the wire without needing a second
// Mux/full IKE session.
func listenPeer(t *testing.T, network, addr string) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(addr)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func testSendESPBatch(t *testing.T, network, addr string) {
	peer := listenPeer(t, network, addr)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	m, err := Dial("", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// A batch larger than Bind's limit exercises sendESPLoop's splitting and
	// pending-batch handling as well as the ordinary batched send path.
	const n = 200
	batch := make([][]byte, n)
	for i := 0; i < n; i++ {
		batch[i] = []byte{byte(i), byte(i >> 8)}
	}
	if err := m.SendESPBatch(batch); err != nil {
		t.Fatalf("SendESPBatch: %v", err)
	}

	got := map[int]bool{}
	buf := make([]byte, 64)
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < n; i++ {
		rn, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read %d/%d: %v", i, n, err)
		}
		if rn != 2 {
			t.Fatalf("unexpected packet length %d, want 2", rn)
		}
		got[int(buf[0])|int(buf[1])<<8] = true
	}
	if len(got) != n {
		t.Fatalf("got %d distinct packets, want %d", len(got), n)
	}
}

func TestSendESPBatchIPv4(t *testing.T) {
	testSendESPBatch(t, "udp4", "127.0.0.1")
}

func TestSendESPBatchIPv6(t *testing.T) {
	testSendESPBatch(t, "udp6", "::1")
}

func TestPackForGSOProvidesCoalescingCapacity(t *testing.T) {
	bufs := [][]byte{
		[]byte("first packet"),
		[]byte("second packet"),
		[]byte("tail"),
	}
	want := make([][]byte, len(bufs))
	for i := range bufs {
		want[i] = append([]byte(nil), bufs[i]...)
	}

	packed := packForGSO(nil, bufs)
	for i := range bufs {
		if string(bufs[i]) != string(want[i]) {
			t.Fatalf("packet %d changed: got %q want %q", i, bufs[i], want[i])
		}
	}
	if spare := cap(bufs[0]) - len(bufs[0]); spare < len(bufs[1])+len(bufs[2]) {
		t.Fatalf("first packet has %d bytes spare capacity, want at least %d", spare, len(bufs[1])+len(bufs[2]))
	}

	// The sender retains and reuses the packed allocation after Bind.Send.
	reused := packForGSO(packed, bufs[:2])
	if cap(reused) != cap(packed) {
		t.Fatalf("packed allocation was not reused: capacity changed from %d to %d", cap(packed), cap(reused))
	}
}

func TestHubFailureIsTerminal(t *testing.T) {
	hub, err := NewHub(":0")
	if err != nil {
		t.Fatal(err)
	}
	mux, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4500)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("receive failed")
	hub.fail(cause)

	if _, err := mux.RecvESP(); !errors.Is(err, cause) {
		t.Fatalf("existing mux error = %v, want %v", err, cause)
	}
	if _, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4501); err == nil {
		t.Fatal("failed hub accepted a new mux")
	}
	if err := hub.Close(); err != nil {
		t.Fatalf("second terminal transition returned an error: %v", err)
	}
}

func TestRecvESPBatchDrainsToDestinationCapacity(t *testing.T) {
	m := &Mux{espCh: make(chan []byte, 3), done: make(chan struct{})}
	m.espCh <- []byte("one")
	m.espCh <- []byte("two")
	m.espCh <- []byte("three")

	batch, err := m.RecvESPBatch(make([][]byte, 0, 2))
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 2 || string(batch[0]) != "one" || string(batch[1]) != "two" {
		t.Fatalf("batch = %q, want [one two]", batch)
	}
	last, err := m.RecvESP()
	if err != nil {
		t.Fatal(err)
	}
	if string(last) != "three" {
		t.Fatalf("remaining packet = %q, want three", last)
	}
}

// TestSendIKEUnbatchedAndMarked confirms SendIKE still writes immediately
// (not queued through the ESP batching path) and always carries the
// 4-byte non-ESP marker, including for what would be the very first
// IKE_SA_INIT request.
func TestSendIKEUnbatchedAndMarked(t *testing.T) {
	peer := listenPeer(t, "udp4", "127.0.0.1")
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	m, err := Dial("", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	payload := []byte("fake ike header")
	if err := m.SendIKE(payload); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64)
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("SendIKE should be written immediately, not queued: %v", err)
	}
	if n != nonESPMarkerLen+len(payload) {
		t.Fatalf("got %d bytes, want %d", n, nonESPMarkerLen+len(payload))
	}
	for _, b := range buf[:nonESPMarkerLen] {
		if b != 0 {
			t.Fatalf("expected a 4-byte zero marker, got %x", buf[:nonESPMarkerLen])
		}
	}
	if string(buf[nonESPMarkerLen:n]) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", buf[nonESPMarkerLen:n], payload)
	}
}

func TestSendIKEToReceivedSourceEndpoint(t *testing.T) {
	configured := listenPeer(t, "udp4", "127.0.0.1")
	rebound := listenPeer(t, "udp4", "127.0.0.1")
	configuredAddr := configured.LocalAddr().(*net.UDPAddr)
	m, err := Dial("", configuredAddr.IP, configuredAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	const spiI = uint64(0x0102030405060708)
	if err := m.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: m.LocalAddr().(*net.UDPAddr).Port}
	request := make([]byte, 28)
	binary.BigEndian.PutUint64(request[:8], spiI)
	if _, err := rebound.WriteToUDP(withMarker(request), dst); err != nil {
		t.Fatal(err)
	}
	_, source, err := m.RecvIKEFromUntil(time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SendIKETo([]byte("response"), source); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	rebound.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := rebound.ReadFromUDP(buf)
	if err != nil || string(buf[nonESPMarkerLen:n]) != "response" {
		t.Fatalf("rebound endpoint response = %q, %v", buf[:n], err)
	}
	m.AdoptEndpoint(source)
	if err := m.SendIKE([]byte("future")); err != nil {
		t.Fatal(err)
	}
	rebound.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = rebound.ReadFromUDP(buf)
	if err != nil || string(buf[nonESPMarkerLen:n]) != "future" {
		t.Fatalf("adopted endpoint response = %q, %v", buf[:n], err)
	}
	configured.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := configured.ReadFromUDP(buf); err == nil {
		t.Fatal("response was also sent to the stale configured endpoint")
	}
}

func withMarker(payload []byte) []byte {
	return append(make([]byte, nonESPMarkerLen), payload...)
}

func testRecvESPBatch(t *testing.T, network, addr string) {
	server := listenPeer(t, network, addr)
	serverAddr := server.LocalAddr().(*net.UDPAddr)

	m, err := Dial("", serverAddr.IP, serverAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.RegisterESP(0xaabbccdd); err != nil {
		t.Fatal(err)
	}
	clientAddr := m.LocalAddr().(*net.UDPAddr)
	// LocalAddr() on this Mux is wildcard-bound ("::" or "0.0.0.0"), which
	// isn't a valid destination — send to the actual loopback address the
	// test is using instead, at the port Dial picked.
	dst := &net.UDPAddr{IP: net.ParseIP(addr), Port: clientAddr.Port}

	// Sent back-to-back with no synchronization, so receiveLoop's batch read
	// has a real chance to pick up more than one of these in a single
	// call — this is the actual code path under test.
	const n = 200
	for i := 0; i < n; i++ {
		pkt := []byte{0xaa, 0xbb, 0xcc, 0xdd, byte(i), byte(i >> 8), 0, 1}
		if _, err := server.WriteToUDP(pkt, dst); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	got := map[int]bool{}
	for i := 0; i < n; i++ {
		pkt, err := m.RecvESP()
		if err != nil {
			t.Fatalf("RecvESP %d/%d: %v", i, n, err)
		}
		got[int(pkt[4])|int(pkt[5])<<8] = true
	}
	if len(got) != n {
		t.Fatalf("got %d distinct packets, want %d", len(got), n)
	}
}

func TestRecvESPBatchIPv4(t *testing.T) {
	testRecvESPBatch(t, "udp4", "127.0.0.1")
}

func TestRecvESPBatchIPv6(t *testing.T) {
	testRecvESPBatch(t, "udp6", "::1")
}

// TestRecvESPAndIKEDemux confirms the receive-side demux (marker present
// -> IKE, absent -> ESP) still works correctly regardless of whether the
// sender used a batched or unbatched write — it's a plain UDP receiver on
// this end either way, unaffected by how the peer chose to send.
func TestRecvESPAndIKEDemux(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverAddr := server.LocalAddr().(*net.UDPAddr)

	// Dial always binds all interfaces regardless of what's passed here
	// (see Dial's doc comment) -- LocalAddr()'s IP is unspecified, only its
	// port is meaningful, so the destination below is built from the
	// known loopback address plus that port, not from LocalAddr() directly.
	m, err := Dial(":0", serverAddr.IP, serverAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.RegisterESP(0xaabbccdd); err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterIKE(0x696b650000000000); err != nil {
		t.Fatal(err)
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: m.LocalAddr().(*net.UDPAddr).Port}
	espPkt := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 1, 'e', 's', 'p'}
	if _, err := server.WriteToUDP(espPkt, clientAddr); err != nil {
		t.Fatal(err)
	}
	ikePkt := append([]byte{0, 0, 0, 0}, append([]byte("ike"), make([]byte, 5)...)...)
	if _, err := server.WriteToUDP(ikePkt, clientAddr); err != nil {
		t.Fatal(err)
	}

	got, err := m.RecvESP()
	if err != nil {
		t.Fatalf("RecvESP: %v", err)
	}
	if string(got) != string(espPkt) {
		t.Fatalf("ESP payload mismatch: got %x want %x", got, espPkt)
	}
	gotIKE, err := m.RecvIKE()
	if err != nil {
		t.Fatalf("RecvIKE: %v", err)
	}
	if string(gotIKE[:3]) != "ike" {
		t.Fatalf("IKE payload mismatch: got %q want %q", gotIKE[:3], "ike")
	}
}

func TestHubRoutesBySPIAndMuxCloseDoesNotCloseHub(t *testing.T) {
	server := listenPeer(t, "udp4", "127.0.0.1")
	serverAddr := server.LocalAddr().(*net.UDPAddr)
	hub, err := NewHub(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	first, err := hub.NewMux(serverAddr.IP, serverAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hub.NewMux(serverAddr.IP, serverAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.RegisterIKE(1); err != nil {
		t.Fatal(err)
	}
	if err := second.RegisterESP(2); err != nil {
		t.Fatal(err)
	}

	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.LocalAddr().(*net.UDPAddr).Port}
	ikePkt := append([]byte{0, 0, 0, 0}, append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, []byte("ike")...)...)
	if _, err := server.WriteToUDP(ikePkt, dst); err != nil {
		t.Fatal(err)
	}
	if got, err := first.RecvIKEUntil(time.Now().Add(time.Second)); err != nil || string(got) != string(ikePkt[4:]) {
		t.Fatalf("RecvIKE = %x, %v", got, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	espPkt := []byte{0, 0, 0, 2, 'e', 's', 'p'}
	if _, err := server.WriteToUDP(espPkt, dst); err != nil {
		t.Fatal(err)
	}
	if got, err := second.RecvESPUntil(time.Now().Add(time.Second)); err != nil || string(got) != string(espPkt) {
		t.Fatalf("RecvESP = %x, %v", got, err)
	}
}
