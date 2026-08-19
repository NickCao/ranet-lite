package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// RekeyIKE replaces the IKE SA while retaining the current Child SAs. Run
// must be active to service the serialized IKE requests.
func (s *Session) RekeyIKE() error {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()

	old := s.currentContext()
	spiI := randUint64Nonzero()
	for spiI == old.spiI {
		spiI = randUint64Nonzero()
	}
	group := uint16(DH_CURVE25519)
	dh, err := GenerateDH(group)
	if err != nil {
		return fmt.Errorf("ike: generate IKE SA rekey DH key: %w", err)
	}
	ni := make([]byte, 32)
	if err := s.fillIKERekeyNonce(ni); err != nil {
		return fmt.Errorf("ike: generate IKE SA rekey nonce: %w", err)
	}
	s.stateMu.Lock()
	s.localRekey = &ikeRekey{old: old, nonce: ni}
	s.stateMu.Unlock()
	defer func() {
		s.stateMu.Lock()
		defer s.stateMu.Unlock()
		if s.localRekey != nil && s.localRekey.old == old {
			s.localRekey = nil
		}
	}()
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, spiI)
	response, err := s.requestLocked(CREATE_CHILD_SA, []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: ikeProposal().Transforms}})},
		{Type: PayloadNonce, Body: EncodeNonce(ni)},
		{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
	})
	if err != nil {
		return fmt.Errorf("ike: IKE SA rekey request: %w", err)
	}

	var sa, nonce, ke *RawPayload
	for i := range response {
		switch response[i].Type {
		case PayloadN:
			n, err := DecodeNotify(response[i].Body)
			if err != nil {
				return fmt.Errorf("ike: invalid IKE SA rekey notify: %w", err)
			}
			if n.Type < 16384 {
				return fmt.Errorf("ike: IKE SA rekey rejected: notify type %d", n.Type)
			}
		case PayloadSA:
			sa = &response[i]
		case PayloadNonce:
			nonce = &response[i]
		case PayloadKE:
			ke = &response[i]
		}
	}
	if sa == nil || nonce == nil || ke == nil || len(nonce.Body) == 0 {
		return fmt.Errorf("ike: incomplete IKE SA rekey response")
	}
	props, err := DecodeSA(sa.Body)
	if err != nil || len(props) != 1 || props[0].Number != 1 || props[0].Protocol != ProtoIKE || len(props[0].SPI) != 8 || len(props[0].Transforms) != 3 {
		return fmt.Errorf("ike: invalid IKE SA rekey proposal")
	}
	suite, err := suiteFromProposal(props[0])
	if err != nil {
		return fmt.Errorf("ike: invalid IKE SA rekey transforms: %w", err)
	}
	if suite.DHGroup != group {
		return fmt.Errorf("ike: IKE SA rekey chose DH group %d, want %d", suite.DHGroup, group)
	}
	for _, selected := range props[0].Transforms {
		matched := false
		for _, offered := range ikeProposal().Transforms {
			if selected == offered {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("ike: IKE SA rekey chose unsupported transform %d/%d", selected.Type, selected.ID)
		}
	}
	spiR := binary.BigEndian.Uint64(props[0].SPI)
	if spiR == 0 {
		return fmt.Errorf("ike: IKE SA rekey returned zero SPI")
	}
	peerGroup, peerPublic, err := DecodeKE(ke.Body)
	if err != nil || peerGroup != group {
		return fmt.Errorf("ike: IKE SA rekey KE group mismatch (got %d, used %d)", peerGroup, group)
	}
	shared, err := dh.SharedSecret(peerPublic)
	if err != nil {
		return fmt.Errorf("ike: IKE SA rekey shared secret: %w", err)
	}
	keys, err := DeriveRekeyedIKEKeys(old.suite.PRFID, old.skD, suite, shared, ni, nonce.Body, spiI, spiR)
	if err != nil {
		return fmt.Errorf("ike: derive IKE SA rekey keys: %w", err)
	}
	newContext := &ikeContext{suite: suite, skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr, spiI: spiI, spiR: spiR}
	// A peer candidate with the larger initiator nonce already replaced old.
	// The peer will retire this lower-nonce candidate; do not displace its
	// winner or send a Delete on the old SA.
	s.stateMu.RLock()
	current, collision := s.current, s.collision
	s.stateMu.RUnlock()
	if current != old {
		return nil
	}
	if collision != nil {
		loser := collision
		if _, err := s.requestOnLocked(loser, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}); err != nil {
			return fmt.Errorf("ike: retire lower-nonce IKE SA: %w", err)
		}
		s.mux.UnregisterIKE(loser.spiI)
		s.stateMu.Lock()
		if s.collision == loser {
			s.collision = nil
		}
		s.stateMu.Unlock()
	}
	if err := s.mux.RegisterIKE(spiI); err != nil {
		return fmt.Errorf("ike: register rekeyed IKE SA: %w", err)
	}
	s.stateMu.Lock()
	s.old = old
	s.current = newContext
	s.stateMu.Unlock()

	if _, err := s.requestOnLocked(old, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}); err != nil {
		return fmt.Errorf("ike: retire replaced IKE SA: %w", err)
	}
	s.mux.UnregisterIKE(old.spiI)
	s.stateMu.Lock()
	if s.old == old {
		s.old = nil
	}
	s.stateMu.Unlock()
	return nil
}

// handleIKERekey accepts a peer-initiated IKE SA rekey. Its response remains
// protected by ctx; the newly-derived context becomes current for subsequent
// exchanges while ctx stays available until the peer deletes it.
func (s *Session) handleIKERekey(ctx *ikeContext, msgID uint32, inner []RawPayload) ([]byte, error) {
	s.stateMu.RLock()
	accept := ctx == s.current && (s.old == nil || s.localRekey != nil) && s.collision == nil
	s.stateMu.RUnlock()
	if !accept {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	var sa, nonce, ke *RawPayload
	for i := range inner {
		switch inner[i].Type {
		case PayloadSA:
			if sa != nil {
				return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
			}
			sa = &inner[i]
		case PayloadNonce:
			if nonce != nil {
				return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
			}
			nonce = &inner[i]
		case PayloadKE:
			if ke != nil {
				return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
			}
			ke = &inner[i]
		case PayloadTSi, PayloadTSr:
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
		}
	}
	if sa == nil || nonce == nil || ke == nil || len(nonce.Body) == 0 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	props, err := DecodeSA(sa.Body)
	if err != nil || len(props) != 1 || props[0].Number != 1 || props[0].Protocol != ProtoIKE || len(props[0].SPI) != 8 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	spiI := binary.BigEndian.Uint64(props[0].SPI)
	if spiI == 0 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	selected, suite, ok := selectIKERekeyProposal(props[0])
	if !ok {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	group, peerPublic, err := DecodeKE(ke.Body)
	if err != nil || group != suite.DHGroup || len(peerPublic) == 0 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	dh, err := GenerateDH(group)
	if err != nil {
		return nil, fmt.Errorf("ike: generate peer IKE rekey DH key: %w", err)
	}
	shared, err := dh.SharedSecret(peerPublic)
	if err != nil {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	nr := make([]byte, 32)
	if err := s.fillIKERekeyNonce(nr); err != nil {
		return nil, fmt.Errorf("ike: generate peer IKE rekey nonce: %w", err)
	}
	spiR := randUint64Nonzero()
	keys, err := DeriveRekeyedIKEKeys(ctx.suite.PRFID, ctx.skD, suite, shared, nonce.Body, nr, spiI, spiR)
	if err != nil {
		return nil, fmt.Errorf("ike: derive peer IKE rekey keys: %w", err)
	}
	if err := s.mux.RegisterIKE(spiI); err != nil {
		return nil, fmt.Errorf("ike: register peer rekeyed IKE SA: %w", err)
	}
	newContext := &ikeContext{suite: suite, skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr, spiI: spiI, spiR: spiR, responder: true}
	s.stateMu.Lock()
	local := s.localRekey
	if local != nil && local.old == ctx && compareIKENonces(nonce.Body, local.nonce) < 0 {
		// RFC 7296 section 2.8 retains the SA whose initiator nonce is larger.
		// Keep this lower-nonce peer candidate reachable until RekeyIKE can
		// delete it after its own candidate is established.
		s.collision = newContext
	} else {
		s.old = ctx
		s.current = newContext
	}
	s.stateMu.Unlock()
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, spiR)
	response := Proposal{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: selected}
	return s.response(ctx, msgID, CREATE_CHILD_SA, []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{response})},
		{Type: PayloadNonce, Body: EncodeNonce(nr)},
		{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
	})
}

func (s *Session) fillIKERekeyNonce(nonce []byte) error {
	if s.ikeRekeyNonce != nil {
		return s.ikeRekeyNonce(nonce)
	}
	_, err := rand.Read(nonce)
	return err
}

// compareIKENonces compares IKE initiator nonces as unsigned integers.
func compareIKENonces(a, b []byte) int {
	a = bytes.TrimLeft(a, "\x00")
	b = bytes.TrimLeft(b, "\x00")
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return bytes.Compare(a, b)
}

func selectIKERekeyProposal(proposal Proposal) ([]Transform, SASuite, bool) {
	offered := ikeProposal().Transforms
	selected := make([]Transform, 0, 3)
	for _, typ := range []TransformType{TransEncr, TransPRF, TransDH} {
		found := false
		for _, want := range offered {
			if want.Type != typ {
				continue
			}
			for _, got := range proposal.Transforms {
				if got == want {
					selected = append(selected, got)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return nil, SASuite{}, false
		}
	}
	suite, err := suiteFromProposal(Proposal{Transforms: selected})
	if err != nil {
		return nil, SASuite{}, false
	}
	return selected, suite, true
}
