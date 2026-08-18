package ike

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

// PeerConfig describes everything needed to establish one IKEv2 SA with a
// single ranet-provisioned strongSwan node: raw Ed25519 pubkey auth (RFC
// 7427, ASN1_DN identity), 0.0.0.0/0::/0 tunnel-mode Child SA, forced UDP
// encapsulation. See ike/const.go for the modern-only crypto this offers.
type PeerConfig struct {
	Organization string

	LocalCommonName string
	LocalSerial     string
	LocalPrivateKey ed25519.PrivateKey

	RemoteCommonName string
	RemoteSerial     string
	RemotePublicKey  ed25519.PublicKey

	LocalAddr  net.IP // "" => wildcard
	LocalPort  int    // 0 => ephemeral
	RemoteAddr net.IP
	RemotePort int // ranet registry endpoint port (often non-standard, e.g. 13000); the only port ever used, IKE and ESP alike
}

// ChildSA is the negotiated ESP keying material and parameters handed to
// the esp package after a successful handshake.
type ChildSA struct {
	EncrID      uint16
	EncrKeyBits uint16
	LocalSPI    uint32 // our inbound SPI == the SPI peer sends packets to
	RemoteSPI   uint32 // peer's inbound SPI == the SPI we send packets to
	InboundKey  []byte // key||salt used to decrypt packets sent to LocalSPI
	OutboundKey []byte // key||salt used to encrypt packets sent to RemoteSPI
}

// Session is an established IKE SA: it owns the shared UDP mux and can
// still service the peer's INFORMATIONAL exchanges (DPD liveness checks,
// deletes) for as long as the ESP Child SA is in use.
type Session struct {
	mux     *transport.Mux
	suite   SASuite
	skD     []byte
	skai    []byte // unused (AEAD ciphers derive no integrity keys)
	skei    []byte
	sker    []byte
	skpi    []byte
	skpr    []byte
	spiI    uint64
	spiR    uint64
	selfMID uint32 // next Message ID *we* allocate for a self-initiated request
	peerMID uint32 // next Message ID expected from a peer-initiated request

	childMu sync.RWMutex
	Child   ChildSA

	handlerMu   sync.RWMutex
	onChild     func(ChildSA) error
	lastTraffic atomic.Int64
}

func (s *Session) Mux() *transport.Mux { return s.mux }

// SetChildHandler installs replacement ESP SAs before Run acknowledges a
// peer-initiated rekey, as required by RFC 7296 section 2.8.
func (s *Session) SetChildHandler(fn func(ChildSA) error) {
	s.handlerMu.Lock()
	s.onChild = fn
	s.handlerMu.Unlock()
}

func (s *Session) replaceChild(child ChildSA) error {
	if err := s.mux.RegisterESP(child.LocalSPI); err != nil {
		return err
	}
	s.handlerMu.RLock()
	fn := s.onChild
	s.handlerMu.RUnlock()
	if fn != nil {
		if err := fn(child); err != nil {
			return err
		}
	}
	s.childMu.Lock()
	s.Child = child
	s.childMu.Unlock()
	return nil
}

func (s *Session) currentChild() ChildSA {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return s.Child
}

// NoteTraffic records successfully authenticated ESP traffic for the DPD
// policy. RFC 7296 section 2.4 treats it as proof that the IKE SA is alive.
func (s *Session) NoteTraffic() { s.lastTraffic.Store(time.Now().UnixNano()) }

const (
	requestTimeout = 2 * time.Second
	maxRetransmits = 5
)

func randUint64Nonzero() uint64 {
	for {
		var b [8]byte
		rand.Read(b[:])
		v := binary.BigEndian.Uint64(b[:])
		if v != 0 {
			return v
		}
	}
}

func randUint32Nonzero() uint32 {
	for {
		var b [4]byte
		rand.Read(b[:])
		v := binary.BigEndian.Uint32(b[:])
		if v != 0 {
			return v
		}
	}
}

// ikeProposal is the single modern-crypto-only IKE SA proposal we offer:
// AES-256-GCM or ChaCha20-Poly1305, PRF-HMAC-SHA-384/256, Curve25519 with
// P-384/P-256 fallback. No legacy transforms, no separate integrity
// transform (all offered ciphers are AEAD).
func ikeProposal() Proposal {
	return Proposal{
		Number:   1,
		Protocol: ProtoIKE,
		Transforms: []Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305},
			{Type: TransPRF, ID: PRF_HMAC_SHA2_384},
			{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			{Type: TransDH, ID: DH_CURVE25519},
			{Type: TransDH, ID: DH_ECP_384},
			{Type: TransDH, ID: DH_ECP_256},
		},
	}
}

func espProposal(spi []byte) Proposal {
	return Proposal{
		Number:   1,
		Protocol: ProtoESP,
		SPI:      spi,
		Transforms: []Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305},
			{Type: TransESN, ID: ESN_NO},
		},
	}
}

// Initiate runs IKE_SA_INIT then IKE_AUTH against cfg.RemoteAddr:RemotePort
// and returns an established Session with one Child SA. It implements
// exactly RFC 7815's minimal-initiator surface plus what ranet's
// strongSwan deployments require: raw Ed25519 signature auth and
// unconditional UDP encapsulation on that one explicit port — every IKE
// message, from IKE_SA_INIT onward, carries the non-ESP marker; there is
// no NAT-T floating to a separate port (no certs, no EAP, no MOBIKE, no
// rekey).
func Initiate(cfg PeerConfig) (*Session, error) {
	local := ""
	if cfg.LocalAddr != nil {
		local = cfg.LocalAddr.String()
	}
	local = fmt.Sprintf("%s:%d", local, cfg.LocalPort)

	mux, err := transport.Dial(local, cfg.RemoteAddr, cfg.RemotePort)
	if err != nil {
		return nil, err
	}

	spiI := randUint64Nonzero()
	group := uint16(DH_CURVE25519)

	var (
		req     []byte
		respRaw []byte
		resp    *Message
		dh      *DHKeyPair
		ni      []byte
	)

	// The responder may reject our preferred DH group with
	// N(INVALID_KE_PAYLOAD, desired-group); retry once with that group.
	for attempt := 0; attempt < 2; attempt++ {
		dh, err = GenerateDH(group)
		if err != nil {
			mux.Close()
			return nil, err
		}
		ni = make([]byte, 32)
		rand.Read(ni)

		hdr := Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0}
		hashAlgos := make([]byte, 6)
		binary.BigEndian.PutUint16(hashAlgos[0:2], HashSHA2_256)
		binary.BigEndian.PutUint16(hashAlgos[2:4], HashSHA2_384)
		binary.BigEndian.PutUint16(hashAlgos[4:6], HashIdentity)
		payloads := []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{ikeProposal()})},
			{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
			{Type: PayloadNonce, Body: EncodeNonce(ni)},
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: hashAlgos})},
		}
		// NAT_DETECTION_SOURCE_IP, RFC 7296 §2.23. Without this notify,
		// the responder has nothing to compare against for our side and
		// apparently doesn't treat the connection as NAT'd even with
		// encap=yes configured — confirmed by inspecting the resulting
		// kernel XFRM state (`ip xfrm state`), which had no `encap` info
		// attached at all, causing every inbound ESP packet to be
		// silently dropped at the kernel's encap_type check
		// (net/xfrm/xfrm_input.c) before authentication is even
		// attempted. strongSwan's own initiator (ike_natd.c,
		// build_natd_payload) handles this identically when force_encap
		// is set: rather than using its real local address (which would
		// only force NAT-T if it happens to mismatch what the responder
		// observes), it hashes a random IPv4 address with port 0,
		// guaranteeing a mismatch so NAT is always assumed — do the same
		// here rather than relying on whatever this socket's wildcard
		// bind address happens to be.
		var fakeAddr [4]byte
		rand.Read(fakeAddr[:])
		srcHash := natDetectionHash(spiI, 0, net.IP(fakeAddr[:]), 0)
		payloads = append(payloads, RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_SOURCE_IP, Data: srcHash})})
		dstHash := natDetectionHash(spiI, 0, cfg.RemoteAddr, uint16(cfg.RemotePort))
		payloads = append(payloads, RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_DESTINATION_IP, Data: dstHash})})

		m := &Message{Header: hdr, Payloads: payloads}
		req = m.Encode()

		// A bare notify-only response is only worth stopping for when it's
		// N_INVALID_KE_PAYLOAD on the first attempt -- the one legitimate
		// signal that lets us make progress by switching Diffie-Hellman
		// group. Anything else unauthenticated (see sendRecv's doc comment)
		// is rejected here, which makes sendRecv keep retransmitting/
		// waiting for the real response instead of surfacing a possibly
		// forged error.
		acceptAttempt := attempt
		respRaw, err = sendRecv(mux, req, func(raw []byte) bool {
			m, err := DecodeMessage(raw)
			if err != nil {
				return false
			}
			if m.find(PayloadSA) != nil {
				return true
			}
			if n := m.find(PayloadN); n != nil && acceptAttempt == 0 {
				nt, err := DecodeNotify(n.Body)
				if err == nil && nt.Type == N_INVALID_KE_PAYLOAD && len(nt.Data) >= 2 {
					return true
				}
			}
			return false
		})
		if err != nil {
			mux.Close()
			return nil, err
		}
		resp, err = DecodeMessage(respRaw)
		if err != nil {
			mux.Close()
			return nil, fmt.Errorf("ike: decode IKE_SA_INIT response: %w", err)
		}
		if resp.find(PayloadSA) == nil {
			// Only reachable for the N_INVALID_KE_PAYLOAD case accept()
			// just validated -- switch group and retry with a fresh request.
			n := resp.find(PayloadN)
			nt, _ := DecodeNotify(n.Body)
			group = binary.BigEndian.Uint16(nt.Data[:2])
			continue
		}
		break
	}

	spiR := resp.Header.SPIResponder
	saPl := resp.find(PayloadSA)
	kePl := resp.find(PayloadKE)
	noncePl := resp.find(PayloadNonce)
	if saPl == nil || kePl == nil || noncePl == nil {
		mux.Close()
		return nil, fmt.Errorf("ike: incomplete IKE_SA_INIT response")
	}
	props, err := DecodeSA(saPl.Body)
	if err != nil || len(props) != 1 {
		mux.Close()
		return nil, fmt.Errorf("ike: bad SA in IKE_SA_INIT response: %v", err)
	}
	suite, err := suiteFromProposal(props[0])
	if err != nil {
		mux.Close()
		return nil, err
	}
	peerGroup, peerPub, err := DecodeKE(kePl.Body)
	if err != nil || peerGroup != group {
		mux.Close()
		return nil, fmt.Errorf("ike: KE group mismatch (got %d, used %d)", peerGroup, group)
	}
	nr := DecodeNonce(noncePl.Body)

	shared, err := dh.SharedSecret(peerPub)
	if err != nil {
		mux.Close()
		return nil, err
	}
	keys, err := DeriveIKEKeys(suite, shared, ni, nr, spiI, spiR)
	if err != nil {
		mux.Close()
		return nil, err
	}

	sess := &Session{
		mux: mux, suite: suite,
		skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr,
		spiI: spiI, spiR: spiR, selfMID: 2, peerMID: 0,
	}

	if err := sess.doIKEAuth(cfg, req, respRaw, ni, nr); err != nil {
		mux.Close()
		return nil, err
	}
	return sess, nil
}

func suiteFromProposal(p Proposal) (SASuite, error) {
	encr, ok := p.ChosenTransform(TransEncr)
	if !ok {
		return SASuite{}, fmt.Errorf("ike: responder chose no encryption transform")
	}
	prfT, ok := p.ChosenTransform(TransPRF)
	if !ok {
		return SASuite{}, fmt.Errorf("ike: responder chose no PRF transform")
	}
	dhT, ok := p.ChosenTransform(TransDH)
	if !ok {
		return SASuite{}, fmt.Errorf("ike: responder chose no DH transform")
	}
	kb := encr.KeyLengthBits
	if encr.ID == ENCR_CHACHA20_POLY1305 {
		kb = 256
	}
	if _, err := aeadParams(encr.ID, kb); err != nil {
		return SASuite{}, fmt.Errorf("ike: responder chose unsupported encryption %d: %w", encr.ID, err)
	}
	if _, err := prfHashFunc(prfT.ID); err != nil {
		return SASuite{}, err
	}
	return SASuite{EncrID: encr.ID, EncrKeyBits: kb, PRFID: prfT.ID, DHGroup: dhT.ID}, nil
}

func (s *Session) doIKEAuth(cfg PeerConfig, realMessage1, realMessage2, ni, nr []byte) error {
	mySPI := randUint32Nonzero()
	spiBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(spiBuf, mySPI)

	idiBody := EncodeID(ID_DER_ASN1_DN, EncodeIdentityDN(cfg.Organization, cfg.LocalCommonName, cfg.LocalSerial))
	idrBody := EncodeID(ID_DER_ASN1_DN, EncodeIdentityDN(cfg.Organization, cfg.RemoteCommonName, cfg.RemoteSerial))

	macedIDForI := prf(s.suite.PRFID, s.skpi, idiBody)
	signedOctets := concat(realMessage1, nr, macedIDForI)
	authBody := BuildAuth(cfg.LocalPrivateKey, signedOctets)

	tsv4, tsv6 := FullRangeV4(), FullRangeV6()
	inner := []RawPayload{
		{Type: PayloadIDi, Body: idiBody},
		{Type: PayloadIDr, Body: idrBody},
		{Type: PayloadAUTH, Body: authBody},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal(spiBuf)})},
		{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
		{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
	}
	hdr := Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	req, err := EncryptMessage(s.suite, s.skei, hdr, nil, inner)
	if err != nil {
		return err
	}

	// A response with no SK payload is a bare, unauthenticated notify --
	// RFC 7815 §2.1 says to ignore these rather than abort, since anyone
	// able to spoof our SPI can forge one; sendRecv keeps retransmitting
	// until a real (encrypted) response arrives or it times out.
	respRaw, err := sendRecv(s.mux, req, func(raw []byte) bool {
		m, err := DecodeMessage(raw)
		return err == nil && m.find(PayloadSK) != nil
	})
	if err != nil {
		return err
	}
	resp, err := DecodeMessage(respRaw)
	if err != nil {
		return fmt.Errorf("ike: decode IKE_AUTH response: %w", err)
	}
	respInner, err := DecryptMessage(s.suite, s.sker, respRaw, resp)
	if err != nil {
		return err
	}
	respMsg := &Message{Header: resp.Header, Payloads: respInner}

	if n := respMsg.find(PayloadN); n != nil && respMsg.find(PayloadAUTH) == nil {
		nt, _ := DecodeNotify(n.Body)
		return fmt.Errorf("ike: IKE_AUTH rejected inside SK: notify type %d", nt.Type)
	}

	idrRecv := respMsg.find(PayloadIDr)
	authRecv := respMsg.find(PayloadAUTH)
	saRecv := respMsg.find(PayloadSA)
	if idrRecv == nil || authRecv == nil || saRecv == nil {
		return fmt.Errorf("ike: incomplete IKE_AUTH response")
	}
	macedIDForR := prf(s.suite.PRFID, s.skpr, idrRecv.Body)
	responderSigned := concat(realMessage2, ni, macedIDForR)
	if err := VerifyAuth(cfg.RemotePublicKey, responderSigned, authRecv.Body); err != nil {
		return err
	}

	childProps, err := DecodeSA(saRecv.Body)
	if err != nil || len(childProps) != 1 {
		return fmt.Errorf("ike: bad child SA in IKE_AUTH response")
	}
	cp := childProps[0]
	encr, ok := cp.ChosenTransform(TransEncr)
	if !ok {
		return fmt.Errorf("ike: no child encryption transform chosen")
	}
	kb := encr.KeyLengthBits
	if encr.ID == ENCR_CHACHA20_POLY1305 {
		kb = 256
	}
	if len(cp.SPI) != 4 {
		return fmt.Errorf("ike: unexpected child SPI size %d", len(cp.SPI))
	}
	remoteSPI := binary.BigEndian.Uint32(cp.SPI)

	initKey, respKey, err := ChildSAKeymat(s.suite.PRFID, s.skD, ni, nr, encr.ID, kb)
	if err != nil {
		return err
	}
	if err := s.replaceChild(ChildSA{
		EncrID: encr.ID, EncrKeyBits: kb,
		LocalSPI: mySPI, RemoteSPI: remoteSPI,
		InboundKey: respKey, OutboundKey: initKey,
	}); err != nil {
		return err
	}
	return nil
}

// sendRecv sends req and waits for a correlated response, retransmitting on
// timeout. accept is consulted for every response matching req's SPI and
// Message ID: RFC 7815 §2.1 requires ignoring unauthenticated error
// notifications and simply continuing to retransmit until timeout, since an
// IKE_SA_INIT response (and the outer, pre-decryption layer of an IKE_AUTH
// response) carries no integrity protection of its own -- anyone able to
// spoof the initiator's SPI, visible in the plaintext request, can inject a
// forged error notify to abort an in-progress handshake otherwise. accept
// lets each exchange decide what counts as a real response worth stopping
// for; a nil accept treats any correlated response as final.
func sendRecv(mux *transport.Mux, req []byte, accept func([]byte) bool) ([]byte, error) {
	reqHdr, err := decodeHeader(req)
	if err != nil {
		return nil, err
	}
	// Register before the first transmission so a response cannot race the
	// receive loop on a shared hub.
	if err := mux.RegisterIKE(reqHdr.SPIInitiator); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < maxRetransmits; attempt++ {
		if err := mux.SendIKE(req); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(requestTimeout)
		for time.Now().Before(deadline) {
			raw, err := mux.RecvIKEUntil(deadline)
			if err != nil {
				break // timeout, retransmit
			}
			h, err := decodeHeader(raw)
			if err != nil {
				continue
			}
			if h.SPIInitiator == reqHdr.SPIInitiator && h.MessageID == reqHdr.MessageID && h.IsResponse() {
				if accept == nil || accept(raw) {
					return raw, nil
				}
				// Correlated but rejected by accept (e.g. a bare,
				// unauthenticated error notify): keep waiting instead of
				// treating a possibly-forged message as authoritative.
				continue
			}
			// Not our response (e.g. an unrelated request); ignore and keep waiting.
		}
	}
	return nil, fmt.Errorf("ike: no response after %d attempts", maxRetransmits)
}
