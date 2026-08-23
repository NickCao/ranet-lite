package netstack

import (
	"bytes"
	"errors"
	"os"
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

func TestEncryptionWorkersParallelizeOneContainerAndEmitInOrder(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	transmitted := make(chan [][]byte, 1)
	peer := NewPeerBatched("peer", func(raw []byte, _ byte) ([]byte, error) {
		started <- struct{}{}
		<-release
		return raw, nil
	}, func(sealed [][]byte) error {
		batch := make([][]byte, len(sealed))
		for i := range sealed {
			batch[i] = append([]byte(nil), sealed[i]...)
		}
		transmitted <- batch
		return nil
	})

	m := &Mesh{
		encryption: make(chan *outboundElement, 2),
		order:      make(chan *outboundElementsContainer, 1),
	}
	c := &outboundElementsContainer{}
	c.elems = []*outboundElement{
		{peer: peer, raw: []byte{1}, batch: c},
		{peer: peer, raw: []byte{2}, batch: c},
	}
	c.Add(len(c.elems))
	m.order <- c
	m.encryption <- c.elems[0]
	m.encryption <- c.elems[1]
	close(m.encryption)
	close(m.order)

	emitterDone := make(chan struct{})
	go func() {
		m.emitter()
		close(emitterDone)
	}()
	go m.encryptionWorker()
	go m.encryptionWorker()

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("packets from one container did not start concurrently")
		}
	}
	close(release)

	var got [][]byte
	select {
	case got = <-transmitted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ordered transmission")
	}
	<-emitterDone
	if len(got) != 2 || !bytes.Equal(got[0], []byte{1}) || !bytes.Equal(got[1], []byte{2}) {
		t.Fatalf("transmission order = %v, want [[1] [2]]", got)
	}
}

func TestDeliverInboundBatchLeavesCapacityForGRO(t *testing.T) {
	dev := &recordingDevice{
		writes: make(chan recordedWrite, 1),
		events: make(chan tun.Event),
	}
	m := &Mesh{
		dev:     dev,
		inbound: make(chan [][]byte, 1),
		done:    make(chan struct{}),
	}
	go m.inboundLoop()

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
	close(m.done)
}
