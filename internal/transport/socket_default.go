//go:build !linux

package transport

import "github.com/tailscale/wireguard-go/conn"

type portableBind struct{ conn.Bind }
type portableEndpoint struct{ conn.Endpoint }

func (*portableEndpoint) transportEndpoint() {}

func (b *portableBind) ParseEndpoint(s string) (Endpoint, error) {
	ep, err := b.Bind.ParseEndpoint(s)
	return &portableEndpoint{ep}, err
}

func (b *portableBind) Send(packets [][]byte, endpoint Endpoint) error {
	return b.Bind.Send(packets, endpoint.(*portableEndpoint).Endpoint, 0)
}

func openPacketBind(port uint16) (packetBind, []receiveFunc, uint16, error) {
	b := &portableBind{conn.NewStdNetBind()}
	fns, port, err := b.Open(port)
	if err != nil {
		return nil, nil, 0, err
	}
	var receivers []receiveFunc
	for _, fn := range fns {
		size := b.BatchSize()
		slab := make([]byte, readBufferSize*size)
		packets := make([]conn.ReceivedPacket, size)
		receivers = append(receivers, func(bufs [][]byte, sizes []int, endpoints []Endpoint) (int, error) {
			n, err := fn(slab, packets)
			for i := range n {
				bufs[i], sizes[i] = packets[i].Bytes(slab), packets[i].Size
				endpoints[i] = &portableEndpoint{packets[i].Endpoint}
			}
			return n, err
		})
	}
	return b, receivers, port, nil
}
