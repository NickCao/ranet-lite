// babeltest brings up the full client stack (IKE + ESP + TUN device)
// against a real strongSwan responder, then runs the Babel speaker against
// a real peer (e.g. BIRD) on the tunnel's link-local IPv6 address, and
// reports what routes get learned.
package main

import (
	"context"
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

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/netstack"
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
	originate := flag.String("originate", "fd00:88::2/128", "prefix this node announces")
	runFor := flag.Duration("run", 30*time.Second, "how long to run before reporting")
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
	go sess.Run(context.Background())

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

	peer := netstack.NewPeerReserved("bird", func(count int) (netstack.BatchSealer, error) {
		sequenceRange, err := out.ReserveSequenceRange(count)
		if err != nil {
			return nil, err
		}
		return sequenceRange.Seal, nil
	}, sess.Mux().SendESPBatch)

	speaker, err := babel.New(babel.Config{HelloInterval: 4 * time.Second}, mesh)
	if err != nil {
		log.Fatal(err)
	}
	speaker.AddPeer(peer)
	speaker.Originate(netip.MustParsePrefix(*originate))

	go func() {
		for {
			pkt, err := sess.Mux().RecvESP()
			if err != nil {
				log.Printf("mux closed: %v", err)
				return
			}
			plain, _, err := in.Open(pkt)
			if err != nil {
				log.Printf("dropping undecryptable ESP packet: %v", err)
				continue
			}
			if !speaker.Receive(peer, plain) {
				mesh.DeliverInbound(plain)
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), *runFor)
	defer cancel()
	go speaker.Run(ctx)

	fmt.Printf("babel speaker running for %s...\n", *runFor)
	<-ctx.Done()

	fmt.Println("=== routes learned into the mesh ===")
	for _, p := range mesh.Routes.Debug() {
		fmt.Println(p)
	}
}
