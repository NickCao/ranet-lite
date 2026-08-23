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
		devs:   []tun.Device{dev},
		closed: make(chan struct{}),
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

func ipv6TCPPacket(srcPort, dstPort uint16, marker byte) []byte {
	packet := make([]byte, 61)
	packet[0] = 0x60
	packet[4], packet[5] = 0, 21
	packet[6] = 6
	copy(packet[8:24], []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(packet[24:40], []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	packet[40], packet[41] = byte(srcPort>>8), byte(srcPort)
	packet[42], packet[43] = byte(dstPort>>8), byte(dstPort)
	packet[60] = marker
	return packet
}

func TestDeliverInboundBatchUsesFlowAffineQueues(t *testing.T) {
	const queueCount = 8
	devices := make([]tun.Device, queueCount)
	recorders := make([]*recordingDevice, queueCount)
	for i := range devices {
		recorders[i] = &recordingDevice{
			writes: make(chan recordedWrite, 1),
			events: make(chan tun.Event),
		}
		devices[i] = recorders[i]
	}
	m := &Mesh{devs: devices, closed: make(chan struct{})}
	m.startInboundWriters()
	t.Cleanup(m.Close)

	packets := make([][]byte, 0, 32)
	want := make([][][]byte, queueCount)
	for stream := 0; stream < 16; stream++ {
		for sequence := 0; sequence < 2; sequence++ {
			packet := ipv6TCPPacket(uint16(40000+stream), 5201, byte(sequence))
			packets = append(packets, packet)
			lane := int(innerFlowHash(packet) % queueCount)
			want[lane] = append(want[lane], packet)
		}
	}
	m.DeliverInboundBatch(packets)

	active := 0
	for lane, expected := range want {
		if len(expected) == 0 {
			continue
		}
		active++
		select {
		case got := <-recorders[lane].writes:
			if len(got.packets) != len(expected) {
				t.Fatalf("queue %d wrote %d packets, want %d", lane, len(got.packets), len(expected))
			}
			for i := range expected {
				if !bytes.Equal(got.packets[i], expected[i]) {
					t.Fatalf("queue %d packet %d did not preserve flow order", lane, i)
				}
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for queue %d", lane)
		}
	}
	if active < queueCount/2 {
		t.Fatalf("16 TCP streams used only %d/%d queues", active, queueCount)
	}

	forward := ipv6TCPPacket(40000, 5201, 0)
	reverse := ipv6TCPPacket(5201, 40000, 0)
	copy(reverse[8:24], forward[24:40])
	copy(reverse[24:40], forward[8:24])
	if innerFlowHash(forward)%queueCount != innerFlowHash(reverse)%queueCount {
		t.Fatal("opposite directions of one flow mapped to different queues")
	}
}
