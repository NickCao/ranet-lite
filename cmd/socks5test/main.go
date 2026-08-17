// socks5test brings up the full client stack (IKE + ESP + gvisor netstack)
// against a real strongSwan responder, then exposes it as a local SOCKS5
// proxy — for interop/throughput testing with ordinary SOCKS5-unaware
// tools (e.g. iperf3) via proxychains.
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

	"github.com/NickCao/ranet-lite/internal/esp"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/socks5"
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
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 listen address")
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
	if err := mesh.AddLocalAddress(netip.MustParseAddr(*localInner)); err != nil {
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

	srv, err := socks5.New(*socksAddr, mesh)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("SOCKS5 proxy listening on %s, routing into the mesh via %s\n", srv.Addr(), peerAddr)
	log.Fatal(srv.Serve())
}
