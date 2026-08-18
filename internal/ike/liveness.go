package ike

import "fmt"

// Run services the peer's post-handshake INFORMATIONAL requests — DPD
// liveness checks (empty request/response, RFC 7296 §2.4) and SA deletes —
// until the mux is closed or an unrecoverable error occurs. ranet's
// strongSwan connections set dpd_delay=10s/dpd_action=restart, so a client
// that never answers these gets torn down after dpd_timeout; this is not
// optional for a long-lived session.
func (s *Session) Run() error {
	for {
		raw, err := s.mux.RecvIKE()
		if err != nil {
			return err
		}
		hdr, err := decodeHeader(raw)
		if err != nil {
			continue
		}
		if hdr.IsInitiator() || hdr.IsResponse() {
			// Not a peer-initiated request (either our own reply loopback,
			// which can't happen on this channel, or a response to a
			// request we already collected via sendRecv — ignore).
			continue
		}
		outer, err := DecodeMessage(raw)
		if err != nil {
			continue
		}
		inner, err := DecryptMessage(s.suite, s.sker, raw, outer)
		if err != nil {
			continue
		}
		switch hdr.ExchangeType {
		case INFORMATIONAL:
			if del := findType(inner, PayloadD); del != nil {
				// Minimal handling: ack and stop trusting the Child SA.
				// ranet's connections use close_action=none / dpd_action
				// restart, so a full SA is expected to be re-established
				// by a fresh Initiate call rather than repaired in place.
				s.Child = ChildSA{}
			}
			if err := s.respondEmpty(hdr.MessageID); err != nil {
				return err
			}
		case CREATE_CHILD_SA:
			// No CREATE_CHILD_SA (rekey, additional Child SA) support in
			// this minimal client. RFC 7815 §2.2 MUST: reject with
			// NO_ADDITIONAL_SAS rather than an empty response, so the peer
			// knows definitively not to retry.
			if err := s.respondNotify(hdr.MessageID, CREATE_CHILD_SA, N_NO_ADDITIONAL_SAS); err != nil {
				return err
			}
		default:
			// Nothing else is expected from a real strongSwan peer against
			// this client; silently ack so it doesn't retransmit forever,
			// rather than leaving it unanswered.
			if err := s.respondEmpty(hdr.MessageID); err != nil {
				return err
			}
		}
	}
}

func findType(payloads []RawPayload, t PayloadType) *RawPayload {
	for i := range payloads {
		if payloads[i].Type == t {
			return &payloads[i]
		}
	}
	return nil
}

func (s *Session) respondEmpty(msgID uint32) error {
	hdr := Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: INFORMATIONAL,
		Flags: FlagInitiator | FlagResponse, MessageID: msgID}
	raw, err := EncryptMessage(s.suite, s.skei, hdr, nil, nil)
	if err != nil {
		return fmt.Errorf("ike: build INFORMATIONAL response: %w", err)
	}
	return s.mux.SendIKE(raw)
}

// respondNotify replies to a peer-initiated request with a single Notify
// payload inside SK{}, e.g. SK{N(NO_ADDITIONAL_SAS)} for a rejected
// CREATE_CHILD_SA (RFC 7815 §2.2).
func (s *Session) respondNotify(msgID uint32, exchange ExchangeType, notifyType NotifyType) error {
	hdr := Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: exchange,
		Flags: FlagInitiator | FlagResponse, MessageID: msgID}
	inner := []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: notifyType})}}
	raw, err := EncryptMessage(s.suite, s.skei, hdr, nil, inner)
	if err != nil {
		return fmt.Errorf("ike: build %v response: %w", exchange, err)
	}
	return s.mux.SendIKE(raw)
}
