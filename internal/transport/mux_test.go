package transport

import (
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

	// Sent back-to-back with no synchronization, so sendESPLoop's
	// non-blocking drain has a real chance to coalesce more than one of
	// these into a single WriteBatch call — this is the actual code path
	// under test, not just "does a single SendESP still work".
	const n = 200
	for i := 0; i < n; i++ {
		if err := m.SendESP([]byte{byte(i), byte(i >> 8)}); err != nil {
			t.Fatalf("SendESP %d: %v", i, err)
		}
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

func testRecvESPBatch(t *testing.T, network, addr string) {
	server := listenPeer(t, network, addr)
	serverAddr := server.LocalAddr().(*net.UDPAddr)

	m, err := Dial("", serverAddr.IP, serverAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	clientAddr := m.LocalAddr().(*net.UDPAddr)
	// LocalAddr() on this Mux is wildcard-bound ("::" or "0.0.0.0"), which
	// isn't a valid destination — send to the actual loopback address the
	// test is using instead, at the port Dial picked.
	dst := &net.UDPAddr{IP: net.ParseIP(addr), Port: clientAddr.Port}

	// Sent back-to-back with no synchronization, so readLoop's ReadBatch
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
	// Dual-stack, matching how Mux itself always binds (Dial resolves ""
	// against network "udp") — a udp4-only socket can't address a peer
	// whose LocalAddr() comes back in IPv6-wildcard form ("[::]:port"),
	// even though the underlying socket is perfectly reachable over IPv4.
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverAddr := server.LocalAddr().(*net.UDPAddr)

	// Bind to a real loopback address, not "" (wildcard "any interface"):
	// LocalAddr() on a wildcard-bound socket reports the unspecified
	// address itself ("::"), which isn't a valid destination to write to.
	m, err := Dial("127.0.0.1:0", serverAddr.IP, serverAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	clientAddr := m.LocalAddr().(*net.UDPAddr)
	espPkt := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 1, 'e', 's', 'p'}
	if _, err := server.WriteToUDP(espPkt, clientAddr); err != nil {
		t.Fatal(err)
	}
	ikePkt := append([]byte{0, 0, 0, 0}, []byte("ike")...)
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
	if string(gotIKE) != "ike" {
		t.Fatalf("IKE payload mismatch: got %q want %q", gotIKE, "ike")
	}
}
