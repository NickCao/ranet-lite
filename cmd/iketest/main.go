// iketest is a throwaway interop-test harness: it runs one IKEv2 initiator
// handshake against a real strongSwan responder and prints the negotiated
// Child SA. Used to validate internal/ike against the netns test rig before
// wiring it into the real client.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/NickCao/ranet-lite/internal/ike"
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
	localAddr := flag.String("local", "10.99.0.1", "local address")
	remoteAddr := flag.String("remote", "10.99.0.2", "remote address")
	remotePort := flag.Int("port", 500, "remote IKE port")
	privPath := flag.String("priv", "/root/ike/testpki/org_priv.pem", "org private key")
	pubPath := flag.String("pub", "/root/ike/testpki/org_pub.pem", "org public key")
	runSeconds := flag.Int("run", 0, "seconds to keep servicing DPD/INFORMATIONAL after handshake")
	childRekey := flag.Duration("child-rekey", 0, "proactively rekey Child SAs at this interval (0 disables)")
	ikeRekey := flag.Duration("ike-rekey", 0, "proactively rekey IKE SAs at this interval (0 disables)")
	flag.Parse()

	cfg := ike.PeerConfig{
		Organization:       "testorg",
		LocalCommonName:    "client",
		LocalSerial:        "2",
		LocalPrivateKey:    loadPriv(*privPath),
		RemoteCommonName:   "server",
		RemoteSerial:       "1",
		RemotePublicKey:    loadPub(*pubPath),
		LocalAddr:          net.ParseIP(*localAddr),
		RemoteAddr:         net.ParseIP(*remoteAddr),
		RemotePort:         *remotePort,
		ChildRekeyInterval: *childRekey,
		IKERekeyInterval:   *ikeRekey,
	}

	sess, err := ike.Initiate(cfg)
	if err != nil {
		log.Fatalf("handshake failed: %v", err)
	}
	fmt.Printf("handshake OK: child SA local_spi=%08x remote_spi=%08x encr=%d keybits=%d\n",
		sess.Child.LocalSPI, sess.Child.RemoteSPI, sess.Child.EncrID, sess.Child.EncrKeyBits)

	if *runSeconds > 0 {
		if *childRekey > 0 || *ikeRekey > 0 {
			fmt.Printf("rekey schedule: child=%s ike=%s\n", *childRekey, *ikeRekey)
		}
		go func() {
			if err := sess.Run(); err != nil {
				log.Printf("session loop ended: %v", err)
			}
		}()
		time.Sleep(time.Duration(*runSeconds) * time.Second)
		fmt.Println("done running")
	}
}
