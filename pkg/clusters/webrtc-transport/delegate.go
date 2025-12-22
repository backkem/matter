package webrtctransport

import "context"

// ProviderDelegate is implemented by the application layer to handle
// WebRTC signaling events on the Provider (device) side.
//
// The delegate is responsible for managing the actual WebRTC PeerConnection
// and translating between Matter signaling and WebRTC operations.
type ProviderDelegate interface {
	// OnSolicitOffer is called when a SolicitOffer command is received.
	// Returns whether the offer will be deferred (e.g., device waking from standby).
	// The delegate should later call Provider.SendOffer() when ready.
	OnSolicitOffer(ctx context.Context, req *SolicitOfferRequest) (deferredOffer bool, err error)

	// OnOfferReceived is called when a ProvideOffer command is received.
	// The delegate should process the SDP offer and return an answer.
	OnOfferReceived(ctx context.Context, req *ProvideOfferRequest) (*ProvideOfferResult, error)

	// OnAnswerReceived is called when a ProvideAnswer command is received.
	// This happens in the SolicitOffer flow after the Provider sent an Offer.
	OnAnswerReceived(ctx context.Context, sessionID uint16, sdp string) error

	// OnICECandidates is called when ProvideICECandidates command is received.
	OnICECandidates(ctx context.Context, sessionID uint16, candidates []ICECandidateStruct) error

	// OnSessionEnded is called when EndSession command is received.
	OnSessionEnded(ctx context.Context, sessionID uint16, reason WebRTCEndReasonEnum) error
}

// RequestorDelegate is implemented by the application layer to handle
// WebRTC signaling events on the Requestor (controller) side.
type RequestorDelegate interface {
	// OnOffer is called when an Offer command is received from the Provider.
	// This happens in the SolicitOffer flow when the Provider sends its offer.
	OnOffer(ctx context.Context, sessionID uint16, sdp string, iceServers []ICEServerStruct, iceTransportPolicy string) error

	// OnAnswer is called when an Answer command is received from the Provider.
	// This happens after the Requestor sent a ProvideOffer.
	OnAnswer(ctx context.Context, sessionID uint16, sdp string) error

	// OnICECandidates is called when ICECandidates command is received.
	OnICECandidates(ctx context.Context, sessionID uint16, candidates []ICECandidateStruct) error

	// OnEnd is called when End command is received from the Provider.
	OnEnd(ctx context.Context, sessionID uint16, reason WebRTCEndReasonEnum) error
}

// SolicitOfferRequest contains the parameters for a SolicitOffer command.
type SolicitOfferRequest struct {
	SessionID           uint16 // Assigned by Provider
	StreamUsage         StreamUsageEnum
	OriginatingEndpoint uint16
	VideoStreamID       *uint16 // nullable - nil means no video, ptr to nil means auto-select
	AudioStreamID       *uint16 // nullable - nil means no audio, ptr to nil means auto-select
	ICEServers          []ICEServerStruct
	ICETransportPolicy  string
	MetadataEnabled     bool
	SFrameConfig        *SFrameStruct
}

// ProvideOfferRequest contains the parameters for a ProvideOffer command.
type ProvideOfferRequest struct {
	SessionID           *uint16 // nil for new session, non-nil for re-offer
	SDP                 string
	StreamUsage         StreamUsageEnum
	OriginatingEndpoint uint16
	VideoStreamID       *uint16
	AudioStreamID       *uint16
	ICEServers          []ICEServerStruct
	ICETransportPolicy  string
	MetadataEnabled     bool
	SFrameConfig        *SFrameStruct
}

// ProvideOfferResult is returned by the delegate after processing an offer.
type ProvideOfferResult struct {
	AnswerSDP     string  // SDP answer to send back
	VideoStreamID *uint16 // Allocated video stream ID (or nil)
	AudioStreamID *uint16 // Allocated audio stream ID (or nil)
}

// ICECandidatesCallback is called by the delegate when it has ICE candidates to send.
type ICECandidatesCallback func(sessionID uint16, candidates []ICECandidateStruct) error

// AnswerCallback is called by the delegate when it has an SDP answer to send.
type AnswerCallback func(sessionID uint16, sdp string) error
