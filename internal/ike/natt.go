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
// unconditionally, on the one explicit registry port, regardless of
// whether a NAT is actually present — this client always sends both
// notifications for spec compliance but never acts on the comparison:
// every IKE message is marker-prefixed from IKE_SA_INIT onward and there
// is no separate NAT-T port to float to.
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
