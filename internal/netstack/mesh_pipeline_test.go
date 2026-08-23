package netstack

import (
	"bytes"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

type recordedWrite struct {
	packets  [][]byte
	capacity []int
	offset   int
}

type recordingDevice struct {
	writes chan recordedWrite
	events chan tun.Event
}

func (d *recordingDevice) File() *os.File { return nil }
func (d *recordingDevice) Read([][]byte, []int, int) (int, error) {
	return 0, errors.New("not implemented")
}
func (d *recordingDevice) Write(bufs [][]byte, offset int) (int, error) {
	w := recordedWrite{
		packets:  make([][]byte, len(bufs)),
		capacity: make([]int, len(bufs)),
		offset:   offset,
	}
	for i := range bufs {
		w.packets[i] = append([]byte(nil), bufs[i][offset:]...)
		w.capacity[i] = cap(bufs[i])
	}
	d.writes <- w
	return len(bufs), nil
}
func (d *recordingDevice) MTU() (int, error)        { return DefaultMTU, nil }
func (d *recordingDevice) Name() (string, error)    { return "test0", nil }
func (d *recordingDevice) Events() <-chan tun.Event { return d.events }
func (d *recordingDevice) Close() error             { return nil }
func (d *recordingDevice) BatchSize() int           { return 128 }

func TestReservedPeerBatchesEncryptParallelAndTransmitInOrder(t *testing.T) {
	started := make(chan byte, 2)
	releaseFirst := make(chan struct{})
	transmitted := make(chan byte, 2)
	nextSequence := byte(1)
	peer := NewPeerReserved("peer", func(count int) (BatchSealer, error) {
		first := nextSequence
		nextSequence += byte(count)
		next := first
		return func(raw []byte, _ byte) ([]byte, error) {
			started <- raw[0]
			if raw[0] == 1 {
				<-releaseFirst
			}
			sealed := []byte{next, raw[0]}
			next++
			return sealed, nil
		}, nil
	}, func(sealed [][]byte) error {
		transmitted <- sealed[0][0]
		return nil
	})
	defer peer.Close()

	first := peer.reserveBatch(1)
	second := peer.reserveBatch(1)
	var wg sync.WaitGroup
	for i, b := range []*peerBatch{first, second} {
		wg.Add(1)
		go func(raw byte, b *peerBatch) {
			defer wg.Done()
			b.seal([]byte{raw}, 0)
			if err := b.transmit(); err != nil {
				t.Errorf("transmit batch %d: %v", raw, err)
			}
		}(byte(i+1), b)
	}

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("reserved batches did not encrypt concurrently")
		}
	}
	select {
	case seq := <-transmitted:
		t.Fatalf("later sequence %d transmitted while the first batch was encrypting", seq)
	default:
	}
	close(releaseFirst)
	wg.Wait()
	close(transmitted)

	var got []byte
	for seq := range transmitted {
		got = append(got, seq)
	}
	if !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("transmission sequence order = %v, want [1 2]", got)
	}
}

func TestReservedPeerWorkersDoNotWaitForOrderedSender(t *testing.T) {
	startedSend := make(chan struct{})
	releaseSend := make(chan struct{})
	var releaseOnce sync.Once
	transmitted := make(chan byte, 2)
	nextSequence := byte(1)
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) {
		sequence := nextSequence
		nextSequence++
		return func([]byte, byte) ([]byte, error) { return []byte{sequence}, nil }, nil
	}, func(sealed [][]byte) error {
		if sealed[0][0] == 1 {
			close(startedSend)
			<-releaseSend
		}
		transmitted <- sealed[0][0]
		return nil
	})
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseSend) })
		peer.Close()
	})

	first := peer.reserveBatch(1)
	first.seal([]byte{1}, 0)
	if err := first.enqueue(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-startedSend:
	case <-time.After(time.Second):
		t.Fatal("ordered sender did not start the first batch")
	}

	second := peer.reserveBatch(1)
	second.seal([]byte{2}, 0)
	enqueued := make(chan error, 1)
	go func() { enqueued <- second.enqueue() }()
	select {
	case err := <-enqueued:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker waited for the ordered sender instead of enqueueing its batch")
	}

	releaseOnce.Do(func() { close(releaseSend) })
	for want := byte(1); want <= 2; want++ {
		select {
		case got := <-transmitted:
			if got != want {
				t.Fatalf("transmitted sequence %d, want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for transmitted sequence %d", want)
		}
	}
}

func TestDeliverInboundBatchLeavesCapacityForGRO(t *testing.T) {
	dev := &recordingDevice{
		writes: make(chan recordedWrite, 1),
		events: make(chan tun.Event),
	}
	m := &Mesh{
		dev: dev,
	}

	want := [][]byte{{1, 2, 3}, {4, 5, 6, 7}}
	m.DeliverInboundBatch(want)

	select {
	case got := <-dev.writes:
		if got.offset != writeOffset {
			t.Fatalf("write offset = %d, want %d", got.offset, writeOffset)
		}
		if len(got.packets) != len(want) {
			t.Fatalf("wrote %d packets, want %d", len(got.packets), len(want))
		}
		for i := range want {
			if !bytes.Equal(got.packets[i], want[i]) {
				t.Errorf("packet %d = %v, want %v", i, got.packets[i], want[i])
			}
			if got.capacity[i] < inboundPacketBufferSize {
				t.Errorf("packet %d capacity = %d, want at least %d for GRO", i, got.capacity[i], inboundPacketBufferSize)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for inbound TUN write")
	}
}
