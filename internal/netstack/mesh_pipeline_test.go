package netstack

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
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
func (d *recordingDevice) Read([]byte, []tun.ReadPacket) (int, error) {
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

type recordingMultiQueueDevice struct {
	*recordingDevice
	devices []*recordingDevice
}

func (d *recordingMultiQueueDevice) Queues() []tun.Queue {
	queues := make([]tun.Queue, len(d.devices))
	for i, device := range d.devices {
		queues[i] = device
	}
	return queues
}

func (d *recordingMultiQueueDevice) WriteTo(lane int, bufs [][]byte, offset int) (int, error) {
	return d.devices[lane].Write(bufs, offset)
}

type scriptedReadDevice struct {
	read func([]byte, []tun.ReadPacket) (int, error)
}

func (*scriptedReadDevice) File() *os.File { return nil }
func (d *scriptedReadDevice) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	return d.read(slab, packets)
}

func TestOutboundReaderUsesSlabOffsetsAndProcessesPartialReads(t *testing.T) {
	want := [][]byte{ipv6TCPPacket(40000, 5201, 1), ipv6TCPPacket(40000, 5201, 2)}
	sent := make(chan [][]byte, 1)
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) {
		return func(raw [][]byte, _ []byte, _ [][]byte) ([][]byte, error) {
			out := make([][]byte, len(raw))
			for i := range raw {
				out[i] = bytes.Clone(raw[i])
			}
			return out, nil
		}, nil
	}, func(raw [][]byte) error {
		copyOfBatch := make([][]byte, len(raw))
		for i := range raw {
			copyOfBatch[i] = bytes.Clone(raw[i])
		}
		sent <- copyOfBatch
		return nil
	})
	t.Cleanup(peer.Close)
	reads := 0
	dev := &scriptedReadDevice{read: func(slab []byte, packets []tun.ReadPacket) (int, error) {
		reads++
		if reads > 1 {
			return 0, os.ErrClosed
		}
		offset := tun.ReadPacketSpacing
		for i, packet := range want {
			copy(slab[offset:], packet)
			packets[i] = tun.ReadPacket{Offset: offset, Size: len(packet)}
			offset += len(packet) + tun.ReadPacketSpacing
		}
		return len(want), tun.ErrTooManySegments
	}}
	m := &Mesh{
		Routes: NewRouteTable(), closed: make(chan struct{}),
		outboundJobs: make(chan *outboundBatch, 2), outboundFree: make(chan *outboundBatch, 2),
	}
	m.Routes.Set(netip.MustParsePrefix("::/0"), netip.MustParsePrefix("::/0"), peer)
	for range cap(m.outboundFree) {
		m.outboundFree <- m.newOutboundBatch(len(want))
	}
	m.outboundWorkerWG.Add(1)
	go m.outboundWorker()
	m.outboundReaderWG.Add(1)
	go m.outboundReader(dev)
	t.Cleanup(m.Close)
	select {
	case got := <-sent:
		if len(got) != len(want) {
			t.Fatalf("sent %d packets, want %d", len(got), len(want))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("packet %d = %v, want %v", i, got[i], want[i])
			}
		}
	case <-time.After(time.Second):
		t.Fatal("partial TUN read did not reach the sender")
	}
}

func TestOutboundWorkersEncryptOneQueueInParallelAndTransmitInOrder(t *testing.T) {
	started := make(chan byte, 2)
	releaseFirst := make(chan struct{})
	transmitted := make(chan byte, 2)
	nextSequence := byte(1)
	peer := NewPeerReserved("peer", func(count int) (BatchSealer, error) {
		first := nextSequence
		nextSequence += byte(count)
		next := first
		return func(raw [][]byte, _ []byte, _ [][]byte) ([][]byte, error) {
			sealed := make([][]byte, 0, len(raw))
			for _, packet := range raw {
				started <- packet[0]
				if packet[0] == 1 {
					<-releaseFirst
				}
				sealed = append(sealed, []byte{next, packet[0]})
				next++
			}
			return sealed, nil
		}, nil
	}, func(sealed [][]byte) error {
		for _, packet := range sealed {
			transmitted <- packet[0]
		}
		return nil
	})
	defer peer.Close()

	m := &Mesh{
		closed:       make(chan struct{}),
		outboundJobs: make(chan *outboundBatch, 2),
		outboundFree: make(chan *outboundBatch, 2),
	}
	m.outboundWorkerWG.Add(2)
	go m.outboundWorker()
	go m.outboundWorker()
	defer func() {
		close(m.closed)
		close(m.outboundJobs)
		m.outboundWorkerWG.Wait()
	}()

	for marker := byte(1); marker <= 2; marker++ {
		b := &outboundBatch{
			n:         1,
			bufs:      [][]byte{{marker}},
			peers:     []*Peer{peer},
			headers:   []byte{0},
			counts:    map[*Peer]int{peer: 1},
			batches:   map[*Peer]*peerBatch{peer: peer.reserveBatch(1)},
			peerOrder: []*Peer{peer},
		}
		m.outboundJobs <- b
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
	got := make([]byte, 0, 2)
	for range 2 {
		select {
		case seq := <-transmitted:
			got = append(got, seq)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for ordered transmission")
		}
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
		return func([][]byte, []byte, [][]byte) ([][]byte, error) { return [][]byte{{sequence}}, nil }, nil
	}, func(sealed [][]byte) error {
		if sealed[0][0] == 1 {
			close(startedSend)
			<-releaseSend
		}
		for _, packet := range sealed {
			transmitted <- packet[0]
		}
		return nil
	})
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseSend) })
		peer.Close()
	})

	first := peer.reserveBatch(1)
	first.append([]byte{1}, 0)
	if err := first.enqueue(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-startedSend:
	case <-time.After(time.Second):
		t.Fatal("ordered sender did not start the first batch")
	}

	second := peer.reserveBatch(1)
	second.append([]byte{2}, 0)
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

func TestReservedSenderMergesReadyBatchesAndCompletesEveryTicket(t *testing.T) {
	sendErr := errors.New("send failed")
	cryptoErr := errors.New("crypto failed")
	transmitted := make(chan []byte, 1)
	p := &Peer{
		ID: "peer", completed: make(chan *peerBatch, 3), slots: make(chan struct{}, 3),
		stop: make(chan struct{}), senderDone: make(chan struct{}),
		transmitBatchFn: func(packets [][]byte) error {
			var order []byte
			for _, packet := range packets {
				order = append(order, packet[0])
			}
			transmitted <- order
			return sendErr
		},
	}
	var done []chan error
	for i := range 3 {
		b := &peerBatch{peer: p, ticket: uint64(i), hasSlot: true, done: make(chan error, 1), sealed: [][]byte{{byte(i)}}}
		if i == 1 {
			b.sealed, b.err = nil, cryptoErr
		}
		p.slots <- struct{}{}
		p.completed <- b
		done = append(done, b.done)
	}
	go p.senderLoop()
	defer p.Close()
	select {
	case got := <-transmitted:
		if !bytes.Equal(got, []byte{0, 2}) {
			t.Fatalf("merged transmission = %v, want [0 2]", got)
		}
	case <-time.After(time.Second):
		t.Fatal("ready packets were not transmitted")
	}
	for i, result := range done {
		want := sendErr
		if i == 1 {
			want = cryptoErr
		}
		select {
		case err := <-result:
			if !errors.Is(err, want) {
				t.Fatalf("ticket %d error = %v, want %v", i, err, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("ticket %d never completed", i)
		}
	}
	if len(p.slots) != 0 {
		t.Fatal("merged transmission leaked reservation slots")
	}
}

func TestDeliverInboundBatchUsesPooledBuffersWithHeadroom(t *testing.T) {
	dev := &recordingDevice{
		writes: make(chan recordedWrite, 1),
		events: make(chan tun.Event),
	}
	m := &Mesh{
		dev:    dev,
		queues: tun.QueuesOf(dev),
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
			if got.capacity[i] != inboundPacketBufferSize {
				t.Errorf("packet %d capacity = %d, want %d", i, got.capacity[i], inboundPacketBufferSize)
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
	recorders := make([]*recordingDevice, queueCount)
	for i := range recorders {
		recorders[i] = &recordingDevice{
			writes: make(chan recordedWrite, 1),
			events: make(chan tun.Event),
		}
	}
	dev := &recordingMultiQueueDevice{recordingDevice: recorders[0], devices: recorders}
	m := &Mesh{dev: dev, queues: tun.QueuesOf(dev), closed: make(chan struct{})}
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

func TestCollectReadyInboundCoalescesQueuedDeliveries(t *testing.T) {
	queue := make(chan inboundWriteBatch, 2)
	queue <- inboundWriteBatch{packets: [][]byte{{2}, {3}}}
	queue <- inboundWriteBatch{packets: [][]byte{{4}}}

	got := collectReadyInbound(
		inboundWriteBatch{packets: [][]byte{{1}}},
		queue,
		make([][]byte, 0, inboundWriteBatchSize),
	)
	if len(got) != 4 {
		t.Fatalf("collected %d packets, want 4", len(got))
	}
	for i, packet := range got {
		if len(packet) != 1 || packet[0] != byte(i+1) {
			t.Fatalf("packet %d = %v, want [%d]", i, packet, i+1)
		}
	}
}
