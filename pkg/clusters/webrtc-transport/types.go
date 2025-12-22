package webrtctransport

import (
	"github.com/backkem/matter/pkg/tlv"
)

// Cluster IDs.
const (
	ProviderClusterID  uint32 = 0x0553
	RequestorClusterID uint32 = 0x0554
)

// Cluster revisions.
const (
	ProviderClusterRevision  uint16 = 1
	RequestorClusterRevision uint16 = 1
)

// Provider cluster attribute IDs.
const (
	AttrCurrentSessions uint32 = 0x0000
)

// Provider cluster command IDs.
const (
	CmdSolicitOffer          uint32 = 0x00
	CmdSolicitOfferResponse  uint32 = 0x01
	CmdProvideOffer          uint32 = 0x02
	CmdProvideOfferResponse  uint32 = 0x03
	CmdProvideAnswer         uint32 = 0x04
	CmdProvideICECandidates  uint32 = 0x05
	CmdEndSession            uint32 = 0x06
)

// Requestor cluster command IDs.
const (
	CmdOffer         uint32 = 0x00
	CmdAnswer        uint32 = 0x01
	CmdICECandidates uint32 = 0x02
	CmdEnd           uint32 = 0x03
)

// StreamUsageEnum indicates the usage type of a stream (Spec 11.1.3.1).
type StreamUsageEnum uint8

const (
	StreamUsageInternal  StreamUsageEnum = 0
	StreamUsageRecording StreamUsageEnum = 1
	StreamUsageAnalysis  StreamUsageEnum = 2
	StreamUsageLiveView  StreamUsageEnum = 3
)

// String returns the name of the stream usage.
func (s StreamUsageEnum) String() string {
	switch s {
	case StreamUsageInternal:
		return "Internal"
	case StreamUsageRecording:
		return "Recording"
	case StreamUsageAnalysis:
		return "Analysis"
	case StreamUsageLiveView:
		return "LiveView"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the enum value is valid.
func (s StreamUsageEnum) IsValid() bool {
	return s <= StreamUsageLiveView
}

// WebRTCEndReasonEnum indicates why a WebRTC session ended (Spec 11.4.5.2).
type WebRTCEndReasonEnum uint8

const (
	WebRTCEndReasonICEFailed         WebRTCEndReasonEnum = 0
	WebRTCEndReasonICETimeout        WebRTCEndReasonEnum = 1
	WebRTCEndReasonUserHangup        WebRTCEndReasonEnum = 2
	WebRTCEndReasonUserBusy          WebRTCEndReasonEnum = 3
	WebRTCEndReasonReplaced          WebRTCEndReasonEnum = 4
	WebRTCEndReasonNoUserMedia       WebRTCEndReasonEnum = 5
	WebRTCEndReasonInviteTimeout     WebRTCEndReasonEnum = 6
	WebRTCEndReasonAnsweredElsewhere WebRTCEndReasonEnum = 7
	WebRTCEndReasonOutOfResources    WebRTCEndReasonEnum = 8
	WebRTCEndReasonMediaTimeout      WebRTCEndReasonEnum = 9
	WebRTCEndReasonLowPower          WebRTCEndReasonEnum = 10
	WebRTCEndReasonPrivacyMode       WebRTCEndReasonEnum = 11
	WebRTCEndReasonUnknownReason     WebRTCEndReasonEnum = 12
)

// String returns the name of the end reason.
func (r WebRTCEndReasonEnum) String() string {
	switch r {
	case WebRTCEndReasonICEFailed:
		return "ICEFailed"
	case WebRTCEndReasonICETimeout:
		return "ICETimeout"
	case WebRTCEndReasonUserHangup:
		return "UserHangup"
	case WebRTCEndReasonUserBusy:
		return "UserBusy"
	case WebRTCEndReasonReplaced:
		return "Replaced"
	case WebRTCEndReasonNoUserMedia:
		return "NoUserMedia"
	case WebRTCEndReasonInviteTimeout:
		return "InviteTimeout"
	case WebRTCEndReasonAnsweredElsewhere:
		return "AnsweredElsewhere"
	case WebRTCEndReasonOutOfResources:
		return "OutOfResources"
	case WebRTCEndReasonMediaTimeout:
		return "MediaTimeout"
	case WebRTCEndReasonLowPower:
		return "LowPower"
	case WebRTCEndReasonPrivacyMode:
		return "PrivacyMode"
	case WebRTCEndReasonUnknownReason:
		return "UnknownReason"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the enum value is valid.
func (r WebRTCEndReasonEnum) IsValid() bool {
	return r <= WebRTCEndReasonUnknownReason
}

// ICEServerStruct contains ICE server configuration (Spec 11.4.5.3).
type ICEServerStruct struct {
	URLs       []string // max 10, each max 2000 chars
	Username   *string  // optional, max 508 bytes
	Credential *string  // optional, max 512 bytes
	CAID       *uint16  // optional, 0-65534
}

// MarshalTLV encodes the ICEServerStruct to TLV.
func (s *ICEServerStruct) MarshalTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	// URLs (tag 0) - list of strings
	if err := w.StartArray(tlv.ContextTag(0)); err != nil {
		return err
	}
	for _, url := range s.URLs {
		if err := w.PutString(tlv.Anonymous(), url); err != nil {
			return err
		}
	}
	if err := w.EndContainer(); err != nil {
		return err
	}

	// Username (tag 1) - optional
	if s.Username != nil {
		if err := w.PutString(tlv.ContextTag(1), *s.Username); err != nil {
			return err
		}
	}

	// Credential (tag 2) - optional
	if s.Credential != nil {
		if err := w.PutString(tlv.ContextTag(2), *s.Credential); err != nil {
			return err
		}
	}

	// CAID (tag 3) - optional
	if s.CAID != nil {
		if err := w.PutUint(tlv.ContextTag(3), uint64(*s.CAID)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// UnmarshalTLV decodes the ICEServerStruct from TLV.
func (s *ICEServerStruct) UnmarshalTLV(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidTLV
	}
	if err := r.EnterContainer(); err != nil {
		return err
	}

	for {
		if err := r.Next(); err != nil {
			return err
		}
		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case 0: // URLs
			if r.Type() != tlv.ElementTypeArray {
				return ErrInvalidTLV
			}
			if err := r.EnterContainer(); err != nil {
				return err
			}
			s.URLs = nil
			for {
				if err := r.Next(); err != nil {
					return err
				}
				if r.Type() == tlv.ElementTypeEnd {
					break
				}
				url, err := r.String()
				if err != nil {
					return err
				}
				s.URLs = append(s.URLs, url)
			}
			if err := r.ExitContainer(); err != nil {
				return err
			}
		case 1: // Username
			str, err := r.String()
			if err != nil {
				return err
			}
			s.Username = &str
		case 2: // Credential
			str, err := r.String()
			if err != nil {
				return err
			}
			s.Credential = &str
		case 3: // CAID
			val, err := r.Uint()
			if err != nil {
				return err
			}
			caid := uint16(val)
			s.CAID = &caid
		}
	}

	return r.ExitContainer()
}

// ICECandidateStruct contains an ICE candidate (Spec 11.4.5.4).
type ICECandidateStruct struct {
	Candidate     string  // RFC 8839 candidate-attribute
	SDPMid        *string // nullable
	SDPMLineIndex *uint16 // nullable
}

// MarshalTLV encodes the ICECandidateStruct to TLV.
func (c *ICECandidateStruct) MarshalTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	// Candidate (tag 0)
	if err := w.PutString(tlv.ContextTag(0), c.Candidate); err != nil {
		return err
	}

	// SDPMid (tag 1) - nullable
	if c.SDPMid != nil {
		if err := w.PutString(tlv.ContextTag(1), *c.SDPMid); err != nil {
			return err
		}
	} else {
		if err := w.PutNull(tlv.ContextTag(1)); err != nil {
			return err
		}
	}

	// SDPMLineIndex (tag 2) - nullable
	if c.SDPMLineIndex != nil {
		if err := w.PutUint(tlv.ContextTag(2), uint64(*c.SDPMLineIndex)); err != nil {
			return err
		}
	} else {
		if err := w.PutNull(tlv.ContextTag(2)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// UnmarshalTLV decodes the ICECandidateStruct from TLV.
func (c *ICECandidateStruct) UnmarshalTLV(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidTLV
	}
	if err := r.EnterContainer(); err != nil {
		return err
	}

	for {
		if err := r.Next(); err != nil {
			return err
		}
		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case 0: // Candidate
			str, err := r.String()
			if err != nil {
				return err
			}
			c.Candidate = str
		case 1: // SDPMid
			if r.Type() == tlv.ElementTypeNull {
				c.SDPMid = nil
			} else {
				str, err := r.String()
				if err != nil {
					return err
				}
				c.SDPMid = &str
			}
		case 2: // SDPMLineIndex
			if r.Type() == tlv.ElementTypeNull {
				c.SDPMLineIndex = nil
			} else {
				val, err := r.Uint()
				if err != nil {
					return err
				}
				idx := uint16(val)
				c.SDPMLineIndex = &idx
			}
		}
	}

	return r.ExitContainer()
}

// SFrameStruct contains SFrame encryption configuration (Spec 11.5.5.1).
type SFrameStruct struct {
	CipherSuite uint16 // min 1
	BaseKey     []byte // max 128 bytes
	KID         []byte // 2-8 bytes
}

// MarshalTLV encodes the SFrameStruct to TLV.
func (s *SFrameStruct) MarshalTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(0), uint64(s.CipherSuite)); err != nil {
		return err
	}
	if err := w.PutBytes(tlv.ContextTag(1), s.BaseKey); err != nil {
		return err
	}
	if err := w.PutBytes(tlv.ContextTag(2), s.KID); err != nil {
		return err
	}

	return w.EndContainer()
}

// UnmarshalTLV decodes the SFrameStruct from TLV.
func (s *SFrameStruct) UnmarshalTLV(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidTLV
	}
	if err := r.EnterContainer(); err != nil {
		return err
	}

	for {
		if err := r.Next(); err != nil {
			return err
		}
		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case 0: // CipherSuite
			val, err := r.Uint()
			if err != nil {
				return err
			}
			s.CipherSuite = uint16(val)
		case 1: // BaseKey
			var err error
			s.BaseKey, err = r.Bytes()
			if err != nil {
				return err
			}
		case 2: // KID
			var err error
			s.KID, err = r.Bytes()
			if err != nil {
				return err
			}
		}
	}

	return r.ExitContainer()
}

// WebRTCSessionStruct stores active session state (Spec 11.4.5.5).
// This struct is fabric-scoped.
type WebRTCSessionStruct struct {
	ID              uint16          // WebRTCSessionID
	PeerNodeID      uint64          // node-id
	PeerEndpointID  uint16          // endpoint-no
	StreamUsage     StreamUsageEnum
	VideoStreamID   *uint16 // nullable
	AudioStreamID   *uint16 // nullable
	MetadataEnabled bool
	FabricIndex     uint8 // implicit fabric scope
}

// MarshalTLV encodes the WebRTCSessionStruct to TLV.
func (s *WebRTCSessionStruct) MarshalTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(0), uint64(s.ID)); err != nil {
		return err
	}
	if err := w.PutUint(tlv.ContextTag(1), s.PeerNodeID); err != nil {
		return err
	}
	if err := w.PutUint(tlv.ContextTag(2), uint64(s.PeerEndpointID)); err != nil {
		return err
	}
	if err := w.PutUint(tlv.ContextTag(3), uint64(s.StreamUsage)); err != nil {
		return err
	}

	// VideoStreamID (tag 4) - nullable
	if s.VideoStreamID != nil {
		if err := w.PutUint(tlv.ContextTag(4), uint64(*s.VideoStreamID)); err != nil {
			return err
		}
	} else {
		if err := w.PutNull(tlv.ContextTag(4)); err != nil {
			return err
		}
	}

	// AudioStreamID (tag 5) - nullable
	if s.AudioStreamID != nil {
		if err := w.PutUint(tlv.ContextTag(5), uint64(*s.AudioStreamID)); err != nil {
			return err
		}
	} else {
		if err := w.PutNull(tlv.ContextTag(5)); err != nil {
			return err
		}
	}

	if err := w.PutBool(tlv.ContextTag(6), s.MetadataEnabled); err != nil {
		return err
	}

	// FabricIndex (tag 254) - implicit fabric scope
	if err := w.PutUint(tlv.ContextTag(254), uint64(s.FabricIndex)); err != nil {
		return err
	}

	return w.EndContainer()
}

// UnmarshalTLV decodes the WebRTCSessionStruct from TLV.
func (s *WebRTCSessionStruct) UnmarshalTLV(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidTLV
	}
	if err := r.EnterContainer(); err != nil {
		return err
	}

	for {
		if err := r.Next(); err != nil {
			return err
		}
		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case 0: // ID
			val, err := r.Uint()
			if err != nil {
				return err
			}
			s.ID = uint16(val)
		case 1: // PeerNodeID
			var err error
			s.PeerNodeID, err = r.Uint()
			if err != nil {
				return err
			}
		case 2: // PeerEndpointID
			val, err := r.Uint()
			if err != nil {
				return err
			}
			s.PeerEndpointID = uint16(val)
		case 3: // StreamUsage
			val, err := r.Uint()
			if err != nil {
				return err
			}
			s.StreamUsage = StreamUsageEnum(val)
		case 4: // VideoStreamID
			if r.Type() == tlv.ElementTypeNull {
				s.VideoStreamID = nil
			} else {
				val, err := r.Uint()
				if err != nil {
					return err
				}
				id := uint16(val)
				s.VideoStreamID = &id
			}
		case 5: // AudioStreamID
			if r.Type() == tlv.ElementTypeNull {
				s.AudioStreamID = nil
			} else {
				val, err := r.Uint()
				if err != nil {
					return err
				}
				id := uint16(val)
				s.AudioStreamID = &id
			}
		case 6: // MetadataEnabled
			var err error
			s.MetadataEnabled, err = r.Bool()
			if err != nil {
				return err
			}
		case 254: // FabricIndex
			val, err := r.Uint()
			if err != nil {
				return err
			}
			s.FabricIndex = uint8(val)
		}
	}

	return r.ExitContainer()
}
