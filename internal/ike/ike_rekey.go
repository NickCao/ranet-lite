package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
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
	var (
		dh       *DHKeyPair
		response []RawPayload
		err      error
	)
	for attempt := 0; attempt < 2; attempt++ {
		dh, err = GenerateDH(group)
		if err != nil {
			return fmt.Errorf("ike: generate IKE SA rekey DH key: %w", err)
		}
		response, err = s.requestLocked(CREATE_CHILD_SA, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: ikeProposal().Transforms}})},
			{Type: PayloadNonce, Body: EncodeNonce(ni)},
			{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
		})
		if err != nil {
			return fmt.Errorf("ike: IKE SA rekey request: %w", err)
		}

		var retryGroup uint16
		for i := range response {
			if response[i].Type != PayloadN {
				continue
			}
			notify, err := DecodeNotify(response[i].Body)
			if err != nil {
				return fmt.Errorf("ike: invalid IKE SA rekey notify: %w", err)
			}
			if notify.Type != N_INVALID_KE_PAYLOAD {
				continue
			}
			if len(notify.Data) != 2 {
				return fmt.Errorf("ike: invalid IKE SA rekey INVALID_KE_PAYLOAD data")
			}
			retryGroup = binary.BigEndian.Uint16(notify.Data)
			break
		}
		if retryGroup == 0 {
			break
		}
		if attempt != 0 || !supportedIKEGroup(retryGroup) {
			return fmt.Errorf("ike: IKE SA rekey rejected: requested unsupported DH group %d", retryGroup)
		}
		// RFC 7296 §1.3 permits the responder to select another offered DH
		// group with INVALID_KE_PAYLOAD. Retry as a new CREATE_CHILD_SA
		// exchange, using the requested group in both SA and KE processing.
		group = retryGroup
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
	if sa == nil || nonce == nil || ke == nil || !validNonce(nonce.Body) {
		return fmt.Errorf("ike: incomplete IKE SA rekey response")
	}
	props, err := DecodeSA(sa.Body)
	if err != nil || len(props) != 1 || props[0].Number != 1 || props[0].Protocol != ProtoIKE || len(props[0].SPI) != 8 || len(props[0].Transforms) != 3 {
		return fmt.Errorf("ike: invalid IKE SA rekey proposal")
	}
	selectedProposal := props[0]
	selectedProposal.SPI = nil
	suite, err := suiteFromProposal(selectedProposal)
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
	s.stateMu.RLock()
	collision := s.collision
	localRekey := s.localRekey
	s.stateMu.RUnlock()
	if collision != nil {
		localLoses := lowestNonceBelongsToFirst(ni, nonce.Body, localRekey.peerNonce, localRekey.peerResponseNonce)
		if localLoses {
			slog.Info("ike simultaneous rekey selected peer candidate")
			if err := s.mux.RegisterIKE(spiI); err != nil {
				return fmt.Errorf("ike: register redundant IKE SA: %w", err)
			}
			if _, err := s.requestOnLocked(newContext, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}); err != nil {
				return fmt.Errorf("ike: delete redundant local IKE SA: %w", err)
			}
			s.mux.UnregisterIKE(spiI)
			s.stateMu.Lock()
			s.old = old
			s.current = collision
			s.collision = nil
			s.stateMu.Unlock()
			return nil
		}
		slog.Info("ike simultaneous rekey selected local candidate")
		if _, err := s.requestOnLocked(collision, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}); err != nil {
			return fmt.Errorf("ike: delete redundant peer IKE SA: %w", err)
		}
		s.mux.UnregisterIKE(collision.spiI)
		s.stateMu.Lock()
		if s.collision == collision {
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
	if sa == nil || nonce == nil || ke == nil || !validNonce(nonce.Body) {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	props, err := DecodeSA(sa.Body)
	if err != nil || len(props) == 0 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	group, peerPublic, err := DecodeKE(ke.Body)
	if err != nil || len(peerPublic) == 0 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	var (
		selected         []Transform
		suite            SASuite
		selectedProposal Proposal
		preferredGroup   uint16
	)
	for _, proposal := range props {
		if proposal.Number == 0 || proposal.Protocol != ProtoIKE || len(proposal.SPI) != 8 || binary.BigEndian.Uint64(proposal.SPI) == 0 {
			continue
		}
		candidate, candidateSuite, candidatePreferred, ok := selectIKERekeyProposal(proposal, group)
		if ok {
			selected = candidate
			suite = candidateSuite
			selectedProposal = proposal
			break
		}
		if candidatePreferred != 0 && (preferredGroup == 0 || ikeGroupPreference(candidatePreferred) < ikeGroupPreference(preferredGroup)) {
			preferredGroup = candidatePreferred
		}
	}
	if selected == nil {
		if preferredGroup == 0 {
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
		}
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, preferredGroup)
		// RFC 7296 §1.3 requires INVALID_KE_PAYLOAD, carrying the
		// preferred group, when a proposal is acceptable but its KE payload
		// uses a different group.
		return s.responseNotifyData(ctx, msgID, CREATE_CHILD_SA, N_INVALID_KE_PAYLOAD, data)
	}
	spiI := binary.BigEndian.Uint64(selectedProposal.SPI)
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
	if local != nil && local.old == ctx {
		local.peerNonce = append([]byte(nil), nonce.Body...)
		local.peerResponseNonce = append([]byte(nil), nr...)
		s.collision = newContext
	} else {
		s.old = ctx
		s.current = newContext
	}
	s.stateMu.Unlock()
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, spiR)
	response := Proposal{Number: selectedProposal.Number, Protocol: ProtoIKE, SPI: spi, Transforms: selected}
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

// compareIKENonces compares complete nonce octet strings as specified by RFC
// 7296 section 2.8.2; leading zero octets remain significant.
func compareIKENonces(a, b []byte) int {
	return bytes.Compare(a, b)
}

// lowestNonceBelongsToFirst reports whether the lowest of the four nonces is
// from the first rekey exchange, whose candidate must therefore be deleted.
func lowestNonceBelongsToFirst(firstI, firstR, secondI, secondR []byte) bool {
	lowest := firstI
	first := true
	for _, candidate := range []struct {
		nonce []byte
		first bool
	}{{firstR, true}, {secondI, false}, {secondR, false}} {
		if bytes.Compare(candidate.nonce, lowest) < 0 {
			lowest, first = candidate.nonce, candidate.first
		}
	}
	return first
}

func supportedIKEGroup(group uint16) bool {
	for _, transform := range ikeProposal().Transforms {
		if transform.Type == TransDH && transform.ID == group {
			return true
		}
	}
	return false
}

func ikeGroupPreference(group uint16) int {
	preference := 0
	for _, transform := range ikeProposal().Transforms {
		if transform.Type != TransDH {
			continue
		}
		if transform.ID == group {
			return preference
		}
		preference++
	}
	return preference
}

func selectIKERekeyProposal(proposal Proposal, keGroup uint16) ([]Transform, SASuite, uint16, bool) {
	offered := ikeProposal().Transforms
	selected := make([]Transform, 0, 3)
	for _, typ := range []TransformType{TransEncr, TransPRF} {
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
			return nil, SASuite{}, 0, false
		}
	}
	var preferredDH, matchingDH Transform
	for _, want := range offered {
		if want.Type != TransDH {
			continue
		}
		for _, got := range proposal.Transforms {
			if got != want {
				continue
			}
			if preferredDH.Type == 0 {
				preferredDH = got
			}
			if got.ID == keGroup {
				matchingDH = got
			}
			break
		}
	}
	if preferredDH.Type == 0 {
		return nil, SASuite{}, 0, false
	}
	if matchingDH.Type == 0 {
		return nil, SASuite{}, preferredDH.ID, false
	}
	selected = append(selected, matchingDH)
	suite, err := suiteFromProposal(Proposal{Number: 1, Protocol: ProtoIKE, Transforms: selected})
	if err != nil {
		return nil, SASuite{}, 0, false
	}
	return selected, suite, preferredDH.ID, true
}
