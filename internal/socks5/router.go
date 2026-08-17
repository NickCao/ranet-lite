package socks5

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/go-gost/core/chain"
	"github.com/nickcao/ranet-client/internal/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

// meshRouter implements chain.Router (github.com/go-gost/core/chain) by
// dialing through the ranet mesh's gvisor stack instead of the host's own
// network stack. It's the only glue needed to reuse go-gost's SOCKS5
// handler as-is: everything downstream of Router.Dial is protocol
// handling we don't need to reimplement.
type meshRouter struct {
	mesh *netstack.Mesh
}

func newMeshRouter(mesh *netstack.Mesh) chain.Router {
	return &meshRouter{mesh: mesh}
}

func (r *meshRouter) Options() *chain.RouterOptions {
	return &chain.RouterOptions{}
}

func (r *meshRouter) Dial(ctx context.Context, network, address string, _ ...chain.DialOption) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("socks5: bad address %q: %w", address, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("socks5: bad port %q: %w", portStr, err)
	}

	addr, err := resolveHost(ctx, host)
	if err != nil {
		return nil, err
	}

	proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
	if addr.Is6() {
		proto = ipv6.ProtocolNumber
	}
	fa := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(addr.AsSlice()), Port: uint16(port)}

	switch network {
	case "tcp", "tcp4", "tcp6":
		return gonet.DialContextTCP(ctx, r.mesh.Stack, fa, proto)
	default:
		return nil, fmt.Errorf("socks5: unsupported network %q (only TCP CONNECT is implemented)", network)
	}
}

// Bind (SOCKS5 BIND command, used by legacy active-mode FTP) is out of
// scope for this minimal client.
func (r *meshRouter) Bind(ctx context.Context, network, address string, _ ...chain.BindOption) (net.Listener, error) {
	return nil, fmt.Errorf("socks5: BIND is not supported")
}

// resolveHost accepts either a literal IP or a hostname. Hostnames are
// resolved via the host's normal DNS resolver — this client doesn't run
// its own resolver, matching "minimal feature set": destinations reachable
// only inside the mesh are expected to be addressed by IP.
func resolveHost(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("socks5: resolve %q: %w", host, err)
	}
	addr, ok := netip.AddrFromSlice(ips[0])
	if !ok {
		return netip.Addr{}, fmt.Errorf("socks5: resolve %q: invalid address", host)
	}
	return addr.Unmap(), nil
}
