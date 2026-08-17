// Package babel implements a minimal RFC 8966 Babel speaker, scoped to
// what ranet's tunnel-mesh topology needs: unicast Hello/IHU/Update per
// peer (there is no shared broadcast segment — each peer is its own
// point-to-point link over ESP), RTT-based costing (RFC 9616), and enough
// route state to feed internal/netstack.RouteTable. Not implemented:
// source-specific routing (RFC 9229 SADR), security (RFC 8967), or
// wireless-specific extensions — this speaker interoperates fine with a
// SADR-aware peer (e.g. BIRD's "ipv6 sadr" table) since that extension is
// opt-in per TLV and a plain Update is valid without it.
package babel

const (
	Magic   = 42
	Version = 2
	Port    = 6696

	headerLen = 4 // Magic(1) Version(1) BodyLength(2)
)

// TLV types, RFC 8966 §4.6.
type TLVType uint8

const (
	TLVPad1         TLVType = 0
	TLVPadN         TLVType = 1
	TLVAckReq       TLVType = 2
	TLVAck          TLVType = 3
	TLVHello        TLVType = 4
	TLVIHU          TLVType = 5
	TLVRouterID     TLVType = 6
	TLVNextHop      TLVType = 7
	TLVUpdate       TLVType = 8
	TLVRouteRequest TLVType = 9
	TLVSeqnoRequest TLVType = 10
)

// Sub-TLV types shared by Hello/IHU (and, per RFC 8966, any TLV), §4.6.
const (
	SubTLVPad1 uint8 = 0
	SubTLVPadN uint8 = 1
	// SubTLVTimestamp carries the RTT extension's timestamps, RFC 9616 §6
	// ("Babel Route Selection with Metric Extensions" — confirmed against
	// both the RFC text and BIRD's actual wire encoding, which agree: 3,
	// not the more mnemonic-seeming 4 this was initially miscoded as).
	SubTLVTimestamp uint8 = 3
)

// Address Encodings, RFC 8966 §4.4.
const (
	AEWildcard      uint8 = 0
	AEIPv4          uint8 = 1
	AEIPv6          uint8 = 2
	AEIPv6LinkLocal uint8 = 3
)

// Special metric value meaning "unreachable" / route retraction, RFC 8966 §4.6.9.
const MetricInfinity uint16 = 0xffff
