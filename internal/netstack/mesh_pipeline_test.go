package netstack

import (
	"bytes"
	"testing"
	"time"
)

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
