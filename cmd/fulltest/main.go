// fulltest is the ultimate interop check: real IKEv2 handshake against
// strongSwan, real ESP encap/decap, real gvisor netstack — and a real TCP
// connection dialed through all of it to a plain TCP echo server sitting
// behind the strongSwan responder. If this passes, every layer of the
// client (minus babel and the SOCKS5 front end, which don't affect the
// data path) interoperates correctly end to end.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/nickcao/ranet-client/internal/esp"
	"github.com/nickcao/ranet-client/internal/ike"
	"github.com/nickcao/ranet-client/internal/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func loadPriv(path string) ed25519.PrivateKey {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return k.(ed25519.PrivateKey)
}

func loadPub(path string) ed25519.PublicKey {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return k.(ed25519.PublicKey)
}

func main() {
	localAddr := flag.String("local", "10.99.0.1", "local outer (UDP) address")
	remoteAddr := flag.String("remote", "10.99.0.2", "remote outer (UDP) address")
	remotePort := flag.Int("port", 500, "remote IKE port")
	localInner := flag.String("local-inner", "10.99.1.2", "this node's mesh (inner) address")
	remoteInner := flag.String("remote-inner", "10.99.1.1", "remote peer's mesh (inner) address")
	echoPort := flag.Int("echo-port", 9000, "TCP port of the echo server on the remote inner address")
	privPath := flag.String("priv", "/root/ike/testpki/org_priv.pem", "org private key")
	pubPath := flag.String("pub", "/root/ike/testpki/org_pub.pem", "org public key")
	flag.Parse()

	cfg := ike.PeerConfig{
		Organization:     "testorg",
		LocalCommonName:  "client",
		LocalSerial:      "2",
		LocalPrivateKey:  loadPriv(*privPath),
		RemoteCommonName: "server",
		RemoteSerial:     "1",
		RemotePublicKey:  loadPub(*pubPath),
		LocalAddr:        net.ParseIP(*localAddr),
		RemoteAddr:       net.ParseIP(*remoteAddr),
		RemotePort:       *remotePort,
	}

	sess, err := ike.Initiate(cfg)
	if err != nil {
		log.Fatalf("handshake failed: %v", err)
	}
	fmt.Printf("handshake OK: child SA local_spi=%08x remote_spi=%08x\n", sess.Child.LocalSPI, sess.Child.RemoteSPI)
	go sess.Run()

	out, err := esp.NewOutbound(sess.Child)
	if err != nil {
		log.Fatal(err)
	}
	in, err := esp.NewInbound(sess.Child)
	if err != nil {
		log.Fatal(err)
	}

	mesh, err := netstack.New(0)
	if err != nil {
		log.Fatal(err)
	}
	innerAddr := netip.MustParseAddr(*localInner)
	if err := mesh.AddLocalAddress(innerAddr); err != nil {
		log.Fatal(err)
	}
	peerAddr := netip.MustParseAddr(*remoteInner)
	peer := netstack.NewPeer("server", func(raw []byte, nh byte) error {
		sealed, err := out.Seal(raw, nh)
		if err != nil {
			return err
		}
		return sess.Mux().SendESP(sealed)
	})
	mesh.Routes.Set(netip.PrefixFrom(peerAddr, 32), peer)

	// Inbound pump: decrypt whatever arrives on the ESP channel and inject
	// it into the stack — this is the loop cmd/ranet-client will run per peer.
	go func() {
		for {
			pkt, err := sess.Mux().RecvESP()
			if err != nil {
				log.Printf("mux closed: %v", err)
				return
			}
			plain, nh, err := in.Open(pkt)
			if err != nil {
				log.Printf("dropping undecryptable ESP packet: %v", err)
				continue
			}
			mesh.DeliverInbound(plain, nh)
		}
	}()

	dst := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(peerAddr.AsSlice()), Port: uint16(*echoPort)}
	conn, err := gonet.DialTCP(mesh.Stack, dst, ipv4.ProtocolNumber)
	if err != nil {
		log.Fatalf("dial through mesh failed: %v", err)
	}
	defer conn.Close()
	fmt.Println("TCP connected through the full stack (IKE+ESP+gvisor)")

	const msg = "hello through the whole stack"
	if _, err := conn.Write([]byte(msg)); err != nil {
		log.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		if err != nil {
			log.Fatalf("read: %v", err)
		}
		n += m
	}
	if string(buf) != msg {
		log.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}
	fmt.Println("SUCCESS: full stack round trip verified —", string(buf))
}
