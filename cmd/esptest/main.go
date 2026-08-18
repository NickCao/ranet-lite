// esptest runs an IKEv2 handshake, then hand-builds one ICMP echo request
// inside a raw IPv4 packet, ESP-seals it, and sends it to the strongSwan
// responder's kernel XFRM stack directly. A successful, decryptable ICMP
// echo reply proves the ESP wire framing (AAD, IV placement, nonce,
// padding) is byte-compatible with a real implementation, not just
// internally consistent.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/NickCao/ranet-lite/internal/esp"
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

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildICMPEcho(src, dst net.IP, id, seq uint16, payload []byte) []byte {
	icmp := make([]byte, 8+len(payload))
	icmp[0] = 8 // echo request
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))

	ip := make([]byte, 20+len(icmp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	binary.BigEndian.PutUint16(ip[4:6], 1)
	ip[8] = 64
	ip[9] = 1 // ICMP
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:20]))
	copy(ip[20:], icmp)
	return ip
}

func parseICMPEchoReply(pkt []byte) (id, seq uint16, ok bool) {
	if len(pkt) < 20 || pkt[9] != 1 {
		return 0, 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	icmp := pkt[ihl:]
	if len(icmp) < 8 || icmp[0] != 0 { // 0 = echo reply
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(icmp[4:6]), binary.BigEndian.Uint16(icmp[6:8]), true
}

func main() {
	localAddr := flag.String("local", "10.99.0.1", "local address")
	remoteAddr := flag.String("remote", "10.99.0.2", "remote address")
	remotePort := flag.Int("port", 500, "remote IKE port")
	privPath := flag.String("priv", "/root/ike/testpki/org_priv.pem", "org private key")
	pubPath := flag.String("pub", "/root/ike/testpki/org_pub.pem", "org public key")
	waitSecs := flag.Int("wait", 5, "seconds to wait for an ESP reply")
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
	fmt.Printf("handshake OK: child SA local_spi=%08x remote_spi=%08x encr=%d keybits=%d\n",
		sess.Child.LocalSPI, sess.Child.RemoteSPI, sess.Child.EncrID, sess.Child.EncrKeyBits)

	go sess.Run()

	out, err := esp.NewOutbound(sess.Child)
	if err != nil {
		log.Fatal(err)
	}
	in, err := esp.NewInbound(sess.Child)
	if err != nil {
		log.Fatal(err)
	}

	src, dst := net.ParseIP(*localAddr), net.ParseIP(*remoteAddr)
	icmpPkt := buildICMPEcho(src, dst, 0x1234, 1, []byte("ranet-lite esp interop test"))
	espPkt, err := out.Seal(icmpPkt, esp.NextHeaderIPv4)
	if err != nil {
		log.Fatal(err)
	}
	if err := sess.Mux().SendESP(espPkt); err != nil {
		log.Fatal(err)
	}
	fmt.Println("sent ESP-encapsulated ICMP echo request")

	deadline := time.Now().Add(time.Duration(*waitSecs) * time.Second)
	for time.Now().Before(deadline) {
		reply, err := sess.Mux().RecvESPUntil(deadline)
		if err != nil {
			break
		}
		payload, nh, err := in.Open(reply)
		if err != nil {
			fmt.Printf("(dropped undecryptable ESP packet, %d bytes on wire: %v)\n", len(reply), err)
			continue
		}
		fmt.Printf("decrypted ESP packet: next_header=%d payload=%d bytes: % x\n", nh, len(payload), payload[:min(len(payload), 40)])
		if nh != esp.NextHeaderIPv4 {
			continue
		}
		id, seq, ok := parseICMPEchoReply(payload)
		if !ok {
			fmt.Println("(decrypted IPv4 packet was not a recognized ICMP echo reply)")
			continue
		}
		fmt.Printf("SUCCESS: decrypted ICMP echo reply id=%#x seq=%d from strongSwan's kernel XFRM stack\n", id, seq)
		return
	}
	log.Fatal("timed out waiting for ICMP echo reply")
}
