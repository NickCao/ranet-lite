// gendn prints the strongSwan "asn1dn:#hex" identity string for a given
// organization/common-name/serial-number triple, using the exact same DER
// encoding the ike package uses for IDi/IDr payloads. Used to build test
// swanctl.conf fixtures and to help operators mirror ranet's identity
// scheme when configuring a strongSwan responder by hand.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/nickcao/ranet-client/internal/ike"
)

func main() {
	org := flag.String("org", "", "organization")
	cn := flag.String("cn", "", "common name")
	serial := flag.String("serial", "", "serial number")
	flag.Parse()
	dn := ike.EncodeIdentityDN(*org, *cn, *serial)
	fmt.Printf("asn1dn:#%s\n", hex.EncodeToString(dn))
}
