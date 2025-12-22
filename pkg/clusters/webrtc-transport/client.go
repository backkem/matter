package webrtctransport

import (
	"bytes"

	"github.com/backkem/matter/pkg/tlv"
)

// EncodeProvideOffer encodes a ProvideOffer command for sending to a Provider cluster.
func EncodeProvideOffer(sessionID *uint16, sdp string, streamUsage StreamUsageEnum, originatingEndpoint uint16,
	videoStreamID, audioStreamID *uint16, iceServers []ICEServerStruct, iceTransportPolicy string,
	metadataEnabled bool) ([]byte, error) {

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	// WebRTCSessionID (tag 0) - nullable
	if sessionID != nil {
		if err := w.PutUint(tlv.ContextTag(0), uint64(*sessionID)); err != nil {
			return nil, err
		}
	} else {
		if err := w.PutNull(tlv.ContextTag(0)); err != nil {
			return nil, err
		}
	}

	// SDP (tag 1)
	if err := w.PutString(tlv.ContextTag(1), sdp); err != nil {
		return nil, err
	}

	// StreamUsage (tag 2)
	if err := w.PutUint(tlv.ContextTag(2), uint64(streamUsage)); err != nil {
		return nil, err
	}

	// OriginatingEndpointID (tag 3)
	if err := w.PutUint(tlv.ContextTag(3), uint64(originatingEndpoint)); err != nil {
		return nil, err
	}

	// VideoStreamID (tag 4) - optional/nullable
	if videoStreamID != nil {
		if err := w.PutUint(tlv.ContextTag(4), uint64(*videoStreamID)); err != nil {
			return nil, err
		}
	}

	// AudioStreamID (tag 5) - optional/nullable
	if audioStreamID != nil {
		if err := w.PutUint(tlv.ContextTag(5), uint64(*audioStreamID)); err != nil {
			return nil, err
		}
	}

	// ICEServers (tag 6) - optional
	if len(iceServers) > 0 {
		if err := encodeICEServerList(w, 6, iceServers); err != nil {
			return nil, err
		}
	}

	// ICETransportPolicy (tag 7) - optional
	if iceTransportPolicy != "" {
		if err := w.PutString(tlv.ContextTag(7), iceTransportPolicy); err != nil {
			return nil, err
		}
	}

	// MetadataEnabled (tag 8)
	if err := w.PutBool(tlv.ContextTag(8), metadataEnabled); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncodeProvideAnswer encodes a ProvideAnswer command for sending to a Provider cluster.
func EncodeProvideAnswer(sessionID uint16, sdp string) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutUint(tlv.ContextTag(0), uint64(sessionID)); err != nil {
		return nil, err
	}
	if err := w.PutString(tlv.ContextTag(1), sdp); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncodeProvideICECandidates encodes a ProvideICECandidates command for sending to a Provider cluster.
func EncodeProvideICECandidates(sessionID uint16, candidates []ICECandidateStruct) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutUint(tlv.ContextTag(0), uint64(sessionID)); err != nil {
		return nil, err
	}

	if err := encodeICECandidateList(w, 1, candidates); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncodeEndSession encodes an EndSession command for sending to a Provider cluster.
func EncodeEndSession(sessionID uint16, reason WebRTCEndReasonEnum) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutUint(tlv.ContextTag(0), uint64(sessionID)); err != nil {
		return nil, err
	}
	if err := w.PutUint(tlv.ContextTag(1), uint64(reason)); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncodeOffer encodes an Offer command for sending to a Requestor cluster.
func EncodeOffer(sessionID uint16, sdp string, iceServers []ICEServerStruct, iceTransportPolicy string) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutUint(tlv.ContextTag(0), uint64(sessionID)); err != nil {
		return nil, err
	}
	if err := w.PutString(tlv.ContextTag(1), sdp); err != nil {
		return nil, err
	}

	if len(iceServers) > 0 {
		if err := encodeICEServerList(w, 2, iceServers); err != nil {
			return nil, err
		}
	}

	if iceTransportPolicy != "" {
		if err := w.PutString(tlv.ContextTag(3), iceTransportPolicy); err != nil {
			return nil, err
		}
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncodeAnswer encodes an Answer command for sending to a Requestor cluster.
func EncodeAnswer(sessionID uint16, sdp string) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutUint(tlv.ContextTag(0), uint64(sessionID)); err != nil {
		return nil, err
	}
	if err := w.PutString(tlv.ContextTag(1), sdp); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncodeICECandidates encodes an ICECandidates command for sending to a Requestor cluster.
func EncodeICECandidates(sessionID uint16, candidates []ICECandidateStruct) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutUint(tlv.ContextTag(0), uint64(sessionID)); err != nil {
		return nil, err
	}

	if err := encodeICECandidateList(w, 1, candidates); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncodeEnd encodes an End command for sending to a Requestor cluster.
func EncodeEnd(sessionID uint16, reason WebRTCEndReasonEnum) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutUint(tlv.ContextTag(0), uint64(sessionID)); err != nil {
		return nil, err
	}
	if err := w.PutUint(tlv.ContextTag(1), uint64(reason)); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeProvideOfferResponse decodes a ProvideOfferResponse.
func DecodeProvideOfferResponse(data []byte) (sessionID uint16, videoStreamID, audioStreamID *uint16, err error) {
	r := tlv.NewReader(bytes.NewReader(data))

	if err = r.Next(); err != nil {
		return
	}
	if r.Type() != tlv.ElementTypeStruct {
		err = ErrInvalidTLV
		return
	}
	if err = r.EnterContainer(); err != nil {
		return
	}

	for {
		if err = r.Next(); err != nil {
			err = nil
			break
		}
		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case 0: // WebRTCSessionID
			val, e := r.Uint()
			if e != nil {
				err = e
				return
			}
			sessionID = uint16(val)
		case 1: // VideoStreamID
			if r.Type() == tlv.ElementTypeNull {
				videoStreamID = nil
			} else {
				val, e := r.Uint()
				if e != nil {
					err = e
					return
				}
				id := uint16(val)
				videoStreamID = &id
			}
		case 2: // AudioStreamID
			if r.Type() == tlv.ElementTypeNull {
				audioStreamID = nil
			} else {
				val, e := r.Uint()
				if e != nil {
					err = e
					return
				}
				id := uint16(val)
				audioStreamID = &id
			}
		}
	}

	_ = r.ExitContainer()
	return
}

// --- Encoding helpers ---

func encodeICEServerList(w *tlv.Writer, tagNum uint8, servers []ICEServerStruct) error {
	if err := w.StartArray(tlv.ContextTag(tagNum)); err != nil {
		return err
	}

	for _, server := range servers {
		if err := w.StartStructure(tlv.Anonymous()); err != nil {
			return err
		}

		// URLs (tag 0)
		if err := w.StartArray(tlv.ContextTag(0)); err != nil {
			return err
		}
		for _, url := range server.URLs {
			if err := w.PutString(tlv.Anonymous(), url); err != nil {
				return err
			}
		}
		if err := w.EndContainer(); err != nil {
			return err
		}

		// Username (tag 1) - optional
		if server.Username != nil {
			if err := w.PutString(tlv.ContextTag(1), *server.Username); err != nil {
				return err
			}
		}

		// Credential (tag 2) - optional
		if server.Credential != nil {
			if err := w.PutString(tlv.ContextTag(2), *server.Credential); err != nil {
				return err
			}
		}

		// CAID (tag 3) - optional
		if server.CAID != nil {
			if err := w.PutUint(tlv.ContextTag(3), uint64(*server.CAID)); err != nil {
				return err
			}
		}

		if err := w.EndContainer(); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

func encodeICECandidateList(w *tlv.Writer, tagNum uint8, candidates []ICECandidateStruct) error {
	if err := w.StartArray(tlv.ContextTag(tagNum)); err != nil {
		return err
	}

	for _, c := range candidates {
		if err := w.StartStructure(tlv.Anonymous()); err != nil {
			return err
		}

		if err := w.PutString(tlv.ContextTag(0), c.Candidate); err != nil {
			return err
		}

		if c.SDPMid != nil {
			if err := w.PutString(tlv.ContextTag(1), *c.SDPMid); err != nil {
				return err
			}
		} else {
			if err := w.PutNull(tlv.ContextTag(1)); err != nil {
				return err
			}
		}

		if c.SDPMLineIndex != nil {
			if err := w.PutUint(tlv.ContextTag(2), uint64(*c.SDPMLineIndex)); err != nil {
				return err
			}
		} else {
			if err := w.PutNull(tlv.ContextTag(2)); err != nil {
				return err
			}
		}

		if err := w.EndContainer(); err != nil {
			return err
		}
	}

	return w.EndContainer()
}
