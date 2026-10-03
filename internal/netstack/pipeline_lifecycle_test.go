package netstack

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

func TestOutboundDispatchKeepsMixedPeerReservationsTogether(t *testing.T) {
	firstReserved := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce, firstOnce sync.Once
	secondReserved := make(chan struct{}, 2)
	transmitted := make(chan struct{}, 4)
	sealer := func(raw [][]byte, _ []byte, _ [][]byte) ([][]byte, error) {
		sealed := make([][]byte, len(raw))
		for i := range raw {
			sealed[i] = bytes.Clone(raw[i])
		}
		return sealed, nil
	}
	send := func(packets [][]byte) error {
		for range packets {
			transmitted <- struct{}{}
		}
		return nil
	}
	a := NewPeerReserved("a", func(int) (BatchSealer, error) {
		firstOnce.Do(func() { close(firstReserved); <-releaseFirst })
		return sealer, nil
	}, send)
	b := NewPeerReserved("b", func(int) (BatchSealer, error) {
		secondReserved <- struct{}{}
		return sealer, nil
	}, send)
	m := &Mesh{closed: make(chan struct{}), outboundJobs: make(chan *outboundBatch, 4), outboundFree: make(chan *outboundBatch, 4)}
	m.outboundWorkerWG.Add(2)
	go m.outboundWorker()
	go m.outboundWorker()
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseFirst) })
		m.Close()
		a.Close()
		b.Close()
	})
	dispatch := func(peers []*Peer) {
		batch := &outboundBatch{
			n: 2, bufs: [][]byte{{1}, {2}}, headers: []byte{0, 0}, peers: peers,
			peerOrder: append([]*Peer(nil), peers...), counts: map[*Peer]int{a: 1, b: 1}, batches: make(map[*Peer]*peerBatch),
		}
		m.outboundReaderWG.Add(1)
		go func() { defer m.outboundReaderWG.Done(); m.dispatchOutbound(batch) }()
	}
	dispatch([]*Peer{a, b})
	<-firstReserved
	dispatch([]*Peer{b, a})
	select {
	case <-secondReserved:
		t.Fatal("another reader reserved B before the first mixed batch could be submitted")
	case <-time.After(20 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseFirst) })
	for range 4 {
		select {
		case <-transmitted:
		case <-time.After(time.Second):
			t.Fatal("mixed-peer batches stopped making progress")
		}
	}
}

func TestMeshCloseCancelsReservationsAndDrainsQueuedTickets(t *testing.T) {
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) {
		return func(raw [][]byte, _ []byte, _ [][]byte) ([][]byte, error) { return [][]byte{bytes.Clone(raw[0])}, nil }, nil
	}, func([][]byte) error { return nil })
	defer peer.Close()
	// Keep the sender waiting on its first ticket, filling every reservation
	// slot before a reader attempts one more. Closing Mesh must release that
	// reader even though the peer itself is still open.
	for range cap(peer.slots) {
		peer.reserveBatch(1)
	}
	m := &Mesh{closed: make(chan struct{}), outboundJobs: make(chan *outboundBatch, 4), outboundFree: make(chan *outboundBatch, 4)}
	m.outboundWorkerWG.Add(1)
	go m.outboundWorker()
	m.outboundReaderWG.Add(1)
	go func() {
		defer m.outboundReaderWG.Done()
		m.dispatchOutbound(&outboundBatch{
			n: 1, bufs: [][]byte{{1}}, headers: []byte{0}, peers: []*Peer{peer},
			peerOrder: []*Peer{peer}, counts: map[*Peer]int{peer: 1}, batches: make(map[*Peer]*peerBatch),
		})
	}()
	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		peer.Close()
		<-done
		t.Fatal("Mesh.Close blocked on a peer reservation")
	}
	if len(m.outboundJobs) != 0 {
		t.Fatal("Mesh.Close abandoned queued transmission tickets")
	}
}

func TestSingleQueueInboundSplitsLargeBatches(t *testing.T) {
	dev := &recordingDevice{writes: make(chan recordedWrite, 2)}
	m := &Mesh{dev: dev, queues: tun.QueuesOf(dev), closed: make(chan struct{})}
	packets := make([][]byte, inboundWriteBatchSize+1)
	for i := range packets {
		packets[i] = []byte{byte(i)}
	}
	m.DeliverInboundBatch(packets)
	if len(dev.writes) != 2 {
		t.Fatalf("got %d TUN writes, want two bounded batches", len(dev.writes))
	}
	first, second := <-dev.writes, <-dev.writes
	if len(first.packets) != inboundWriteBatchSize || len(second.packets) != 1 {
		t.Fatal("single-queue delivery exceeded the TUN GRO table capacity")
	}
	if second.packets[0][0] != byte(inboundWriteBatchSize) {
		t.Fatal("split delivery changed packet order")
	}
}
