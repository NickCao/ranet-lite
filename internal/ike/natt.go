package ike

import (
	"crypto/sha1"
	"encoding/binary"
	"net"
)

// natDetectionHash computes the NAT_DETECTION_{SOURCE,DESTINATION}_IP notify
// data, RFC 7296 §2.23: SHA-1(SPIi | SPIr | Address | Port).
//
// ranet's strongSwan connections force UDP encapsulation (`encap: true`)
// regardless of whether a NAT is actually present, so this client always
// sends both notifications and unconditionally follows the responder's lead
// on floating to port 4500 — it does not try to detect NAT itself.
func natDetectionHash(spiI, spiR uint64, ip net.IP, port uint16) []byte {
	h := sha1.New()
	var spi [16]byte
	binary.BigEndian.PutUint64(spi[0:8], spiI)
	binary.BigEndian.PutUint64(spi[8:16], spiR)
	h.Write(spi[:])
	if v4 := ip.To4(); v4 != nil {
		h.Write(v4)
	} else {
		h.Write(ip.To16())
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	h.Write(p[:])
	return h.Sum(nil)
}
