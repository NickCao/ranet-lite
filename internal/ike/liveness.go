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
		default:
			// No CREATE_CHILD_SA (rekey) support in this minimal client;
			// silently ack anything else so the peer doesn't retransmit
			// forever, rather than leaving it unanswered.
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
