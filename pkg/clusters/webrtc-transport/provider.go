package webrtctransport

import (
	"bytes"
	"context"
	"sync"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/tlv"
)

// ProviderConfig provides dependencies for the WebRTC Transport Provider cluster.
type ProviderConfig struct {
	// EndpointID is the endpoint this cluster belongs to.
	EndpointID datamodel.EndpointID

	// Delegate handles WebRTC signaling events.
	Delegate ProviderDelegate

	// OnSendAnswer is called when the Provider needs to send an Answer to the Requestor.
	// This callback should invoke the Answer command on the Requestor cluster.
	OnSendAnswer func(ctx context.Context, session *WebRTCSessionStruct, sdp string) error

	// OnSendICECandidates is called when the Provider needs to send ICE candidates to the Requestor.
	OnSendICECandidates func(ctx context.Context, session *WebRTCSessionStruct, candidates []ICECandidateStruct) error

	// OnSendOffer is called when the Provider needs to send an Offer to the Requestor (SolicitOffer flow).
	OnSendOffer func(ctx context.Context, session *WebRTCSessionStruct, sdp string, iceServers []ICEServerStruct, iceTransportPolicy string) error

	// OnSendEnd is called when the Provider needs to send an End to the Requestor.
	OnSendEnd func(ctx context.Context, session *WebRTCSessionStruct, reason WebRTCEndReasonEnum) error
}

// Provider implements the WebRTC Transport Provider cluster (0x0553).
type Provider struct {
	*datamodel.ClusterBase
	config ProviderConfig

	mu              sync.RWMutex
	sessions        map[uint16]*WebRTCSessionStruct // sessionID -> session
	nextSessionID   uint16
	currentSessions []WebRTCSessionStruct

	attrList []datamodel.AttributeEntry
}

// NewProvider creates a new WebRTC Transport Provider cluster.
func NewProvider(cfg ProviderConfig) *Provider {
	p := &Provider{
		ClusterBase:   datamodel.NewClusterBase(datamodel.ClusterID(ProviderClusterID), cfg.EndpointID, ProviderClusterRevision),
		config:        cfg,
		sessions:      make(map[uint16]*WebRTCSessionStruct),
		nextSessionID: 0,
	}

	p.attrList = p.buildAttributeList()
	return p
}

// buildAttributeList constructs the list of supported attributes.
func (p *Provider) buildAttributeList() []datamodel.AttributeEntry {
	viewPriv := datamodel.PrivilegeView
	attrs := []datamodel.AttributeEntry{
		datamodel.NewReadOnlyAttribute(datamodel.AttributeID(AttrCurrentSessions), datamodel.AttrQualityFabricScoped, viewPriv),
	}
	return datamodel.MergeAttributeLists(attrs)
}

// AttributeList implements datamodel.Cluster.
func (p *Provider) AttributeList() []datamodel.AttributeEntry {
	return p.attrList
}

// AcceptedCommandList implements datamodel.Cluster.
func (p *Provider) AcceptedCommandList() []datamodel.CommandEntry {
	operatePriv := datamodel.PrivilegeOperate
	return []datamodel.CommandEntry{
		datamodel.NewCommandEntry(datamodel.CommandID(CmdSolicitOffer), 0, operatePriv),
		datamodel.NewCommandEntry(datamodel.CommandID(CmdProvideOffer), 0, operatePriv),
		datamodel.NewCommandEntry(datamodel.CommandID(CmdProvideAnswer), 0, operatePriv),
		datamodel.NewCommandEntry(datamodel.CommandID(CmdProvideICECandidates), 0, operatePriv),
		datamodel.NewCommandEntry(datamodel.CommandID(CmdEndSession), 0, operatePriv),
	}
}

// GeneratedCommandList implements datamodel.Cluster.
func (p *Provider) GeneratedCommandList() []datamodel.CommandID {
	return []datamodel.CommandID{
		datamodel.CommandID(CmdSolicitOfferResponse),
		datamodel.CommandID(CmdProvideOfferResponse),
	}
}

// ReadAttribute implements datamodel.Cluster.
func (p *Provider) ReadAttribute(ctx context.Context, req datamodel.ReadAttributeRequest, w *tlv.Writer) error {
	handled, err := p.ReadGlobalAttribute(ctx, req.Path.Attribute, w,
		p.attrList, p.AcceptedCommandList(), p.GeneratedCommandList())
	if handled || err != nil {
		return err
	}

	switch req.Path.Attribute {
	case datamodel.AttributeID(AttrCurrentSessions):
		return p.readCurrentSessions(req.FabricIndex(), w)
	default:
		return datamodel.ErrUnsupportedAttribute
	}
}

// readCurrentSessions writes the CurrentSessions attribute filtered by fabric.
func (p *Provider) readCurrentSessions(fabricIndex fabric.FabricIndex, w *tlv.Writer) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if err := w.StartArray(tlv.Anonymous()); err != nil {
		return err
	}

	for _, session := range p.sessions {
		if fabric.FabricIndex(session.FabricIndex) == fabricIndex {
			if err := session.MarshalTLV(w); err != nil {
				return err
			}
		}
	}

	return w.EndContainer()
}

// WriteAttribute implements datamodel.Cluster.
func (p *Provider) WriteAttribute(ctx context.Context, req datamodel.WriteAttributeRequest, r *tlv.Reader) error {
	return datamodel.ErrUnsupportedWrite
}

// InvokeCommand implements datamodel.Cluster.
func (p *Provider) InvokeCommand(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	switch req.Path.Command {
	case datamodel.CommandID(CmdSolicitOffer):
		return p.handleSolicitOffer(ctx, req, r)
	case datamodel.CommandID(CmdProvideOffer):
		return p.handleProvideOffer(ctx, req, r)
	case datamodel.CommandID(CmdProvideAnswer):
		return p.handleProvideAnswer(ctx, req, r)
	case datamodel.CommandID(CmdProvideICECandidates):
		return p.handleProvideICECandidates(ctx, req, r)
	case datamodel.CommandID(CmdEndSession):
		return p.handleEndSession(ctx, req, r)
	default:
		return nil, datamodel.ErrUnsupportedCommand
	}
}

// allocateSessionID returns a unique session ID.
func (p *Provider) allocateSessionID() uint16 {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to find an unused ID
	for i := 0; i < 65535; i++ {
		id := p.nextSessionID
		p.nextSessionID++
		if p.nextSessionID > 65534 {
			p.nextSessionID = 0
		}
		if _, exists := p.sessions[id]; !exists {
			return id
		}
	}
	return 0 // Should not happen if sessions are properly managed
}

// handleSolicitOffer handles the SolicitOffer command.
func (p *Provider) handleSolicitOffer(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	if p.config.Delegate == nil {
		return nil, ErrNoDelegate
	}

	// Get subject info
	var sourceNodeID uint64
	var fabricIndex uint8
	if req.Subject != nil {
		sourceNodeID = req.Subject.NodeID
		fabricIndex = uint8(req.Subject.FabricIndex)
	}

	// Decode command fields
	solicitReq, err := decodeSolicitOffer(r)
	if err != nil {
		return nil, err
	}

	// Allocate session ID
	sessionID := p.allocateSessionID()
	solicitReq.SessionID = sessionID

	// Create session
	session := &WebRTCSessionStruct{
		ID:              sessionID,
		PeerNodeID:      sourceNodeID,
		PeerEndpointID:  solicitReq.OriginatingEndpoint,
		StreamUsage:     solicitReq.StreamUsage,
		VideoStreamID:   solicitReq.VideoStreamID,
		AudioStreamID:   solicitReq.AudioStreamID,
		MetadataEnabled: solicitReq.MetadataEnabled,
		FabricIndex:     fabricIndex,
	}

	// Store session
	p.mu.Lock()
	p.sessions[sessionID] = session
	p.mu.Unlock()

	// Call delegate
	deferredOffer, err := p.config.Delegate.OnSolicitOffer(ctx, solicitReq)
	if err != nil {
		// Remove session on error
		p.mu.Lock()
		delete(p.sessions, sessionID)
		p.mu.Unlock()
		return nil, err
	}

	// Encode SolicitOfferResponse
	return encodeSolicitOfferResponse(sessionID, deferredOffer, session.VideoStreamID, session.AudioStreamID)
}

// handleProvideOffer handles the ProvideOffer command.
func (p *Provider) handleProvideOffer(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	if p.config.Delegate == nil {
		return nil, ErrNoDelegate
	}

	// Get subject info
	var sourceNodeID uint64
	var fabricIndex uint8
	if req.Subject != nil {
		sourceNodeID = req.Subject.NodeID
		fabricIndex = uint8(req.Subject.FabricIndex)
	}

	// Decode command fields
	offerReq, err := decodeProvideOffer(r)
	if err != nil {
		return nil, err
	}

	var session *WebRTCSessionStruct
	var sessionID uint16

	if offerReq.SessionID != nil {
		// Re-offer flow
		sessionID = *offerReq.SessionID
		p.mu.RLock()
		session = p.sessions[sessionID]
		p.mu.RUnlock()
		if session == nil {
			return nil, ErrSessionNotFound
		}
		// Verify peer
		if session.PeerNodeID != sourceNodeID || session.FabricIndex != fabricIndex {
			return nil, ErrUnauthorized
		}
	} else {
		// New session
		sessionID = p.allocateSessionID()
		session = &WebRTCSessionStruct{
			ID:              sessionID,
			PeerNodeID:      sourceNodeID,
			PeerEndpointID:  offerReq.OriginatingEndpoint,
			StreamUsage:     offerReq.StreamUsage,
			VideoStreamID:   offerReq.VideoStreamID,
			AudioStreamID:   offerReq.AudioStreamID,
			MetadataEnabled: offerReq.MetadataEnabled,
			FabricIndex:     fabricIndex,
		}

		p.mu.Lock()
		p.sessions[sessionID] = session
		p.mu.Unlock()
	}

	// Call delegate
	result, err := p.config.Delegate.OnOfferReceived(ctx, offerReq)
	if err != nil {
		if offerReq.SessionID == nil {
			// Remove newly created session on error
			p.mu.Lock()
			delete(p.sessions, sessionID)
			p.mu.Unlock()
		}
		return nil, err
	}

	// Update session with allocated stream IDs
	p.mu.Lock()
	if result.VideoStreamID != nil {
		session.VideoStreamID = result.VideoStreamID
	}
	if result.AudioStreamID != nil {
		session.AudioStreamID = result.AudioStreamID
	}
	p.mu.Unlock()

	// Encode ProvideOfferResponse
	resp, err := encodeProvideOfferResponse(sessionID, session.VideoStreamID, session.AudioStreamID)
	if err != nil {
		return nil, err
	}

	// Send Answer asynchronously (after returning response)
	if p.config.OnSendAnswer != nil && result.AnswerSDP != "" {
		go func() {
			_ = p.config.OnSendAnswer(context.Background(), session, result.AnswerSDP)
		}()
	}

	return resp, nil
}

// handleProvideAnswer handles the ProvideAnswer command.
func (p *Provider) handleProvideAnswer(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	if p.config.Delegate == nil {
		return nil, ErrNoDelegate
	}

	// Get subject info
	var sourceNodeID uint64
	var fabricIndex uint8
	if req.Subject != nil {
		sourceNodeID = req.Subject.NodeID
		fabricIndex = uint8(req.Subject.FabricIndex)
	}

	// Decode command fields
	sessionID, sdp, err := decodeProvideAnswer(r)
	if err != nil {
		return nil, err
	}

	// Lookup session
	p.mu.RLock()
	session := p.sessions[sessionID]
	p.mu.RUnlock()
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Verify peer
	if session.PeerNodeID != sourceNodeID || session.FabricIndex != fabricIndex {
		return nil, ErrUnauthorized
	}

	// Call delegate
	if err := p.config.Delegate.OnAnswerReceived(ctx, sessionID, sdp); err != nil {
		return nil, err
	}

	return nil, nil // Status-only response
}

// handleProvideICECandidates handles the ProvideICECandidates command.
func (p *Provider) handleProvideICECandidates(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	if p.config.Delegate == nil {
		return nil, ErrNoDelegate
	}

	// Get subject info
	var sourceNodeID uint64
	var fabricIndex uint8
	if req.Subject != nil {
		sourceNodeID = req.Subject.NodeID
		fabricIndex = uint8(req.Subject.FabricIndex)
	}

	// Decode command fields
	sessionID, candidates, err := decodeProvideICECandidates(r)
	if err != nil {
		return nil, err
	}

	// Lookup session
	p.mu.RLock()
	session := p.sessions[sessionID]
	p.mu.RUnlock()
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Verify peer
	if session.PeerNodeID != sourceNodeID || session.FabricIndex != fabricIndex {
		return nil, ErrUnauthorized
	}

	// Call delegate
	if err := p.config.Delegate.OnICECandidates(ctx, sessionID, candidates); err != nil {
		return nil, err
	}

	return nil, nil // Status-only response
}

// handleEndSession handles the EndSession command.
func (p *Provider) handleEndSession(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	// Get subject info
	var sourceNodeID uint64
	var fabricIndex uint8
	if req.Subject != nil {
		sourceNodeID = req.Subject.NodeID
		fabricIndex = uint8(req.Subject.FabricIndex)
	}

	// Decode command fields
	sessionID, reason, err := decodeEndSession(r)
	if err != nil {
		return nil, err
	}

	// Lookup session
	p.mu.Lock()
	session := p.sessions[sessionID]
	if session == nil {
		p.mu.Unlock()
		return nil, ErrSessionNotFound
	}

	// Verify peer
	if session.PeerNodeID != sourceNodeID || session.FabricIndex != fabricIndex {
		p.mu.Unlock()
		return nil, ErrUnauthorized
	}

	// Remove session
	delete(p.sessions, sessionID)
	p.mu.Unlock()

	// Call delegate if set
	if p.config.Delegate != nil {
		_ = p.config.Delegate.OnSessionEnded(ctx, sessionID, reason)
	}

	return nil, nil // Status-only response
}

// SendICECandidates sends ICE candidates to the Requestor.
// Called by the application when new ICE candidates are gathered.
func (p *Provider) SendICECandidates(ctx context.Context, sessionID uint16, candidates []ICECandidateStruct) error {
	if p.config.OnSendICECandidates == nil {
		return ErrNoDelegate
	}

	p.mu.RLock()
	session := p.sessions[sessionID]
	p.mu.RUnlock()
	if session == nil {
		return ErrSessionNotFound
	}

	return p.config.OnSendICECandidates(ctx, session, candidates)
}

// SendOffer sends an SDP offer to the Requestor (SolicitOffer flow).
func (p *Provider) SendOffer(ctx context.Context, sessionID uint16, sdp string, iceServers []ICEServerStruct, iceTransportPolicy string) error {
	if p.config.OnSendOffer == nil {
		return ErrNoDelegate
	}

	p.mu.RLock()
	session := p.sessions[sessionID]
	p.mu.RUnlock()
	if session == nil {
		return ErrSessionNotFound
	}

	return p.config.OnSendOffer(ctx, session, sdp, iceServers, iceTransportPolicy)
}

// EndSession ends a session and notifies the Requestor.
func (p *Provider) EndSession(ctx context.Context, sessionID uint16, reason WebRTCEndReasonEnum) error {
	p.mu.Lock()
	session := p.sessions[sessionID]
	if session == nil {
		p.mu.Unlock()
		return ErrSessionNotFound
	}
	delete(p.sessions, sessionID)
	p.mu.Unlock()

	if p.config.OnSendEnd != nil {
		return p.config.OnSendEnd(ctx, session, reason)
	}
	return nil
}

// GetSession returns a session by ID.
func (p *Provider) GetSession(sessionID uint16) *WebRTCSessionStruct {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sessions[sessionID]
}

// --- TLV Encoding/Decoding Helpers ---

func decodeSolicitOffer(r *tlv.Reader) (*SolicitOfferRequest, error) {
	req := &SolicitOfferRequest{}

	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidTLV
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	for {
		if err := r.Next(); err != nil {
			return nil, err
		}
		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case 0: // StreamUsage
			val, err := r.Uint()
			if err != nil {
				return nil, err
			}
			req.StreamUsage = StreamUsageEnum(val)
		case 1: // OriginatingEndpointID
			val, err := r.Uint()
			if err != nil {
				return nil, err
			}
			req.OriginatingEndpoint = uint16(val)
		case 2: // VideoStreamID
			if r.Type() == tlv.ElementTypeNull {
				// null means auto-select
				empty := uint16(0)
				req.VideoStreamID = &empty
			} else {
				val, err := r.Uint()
				if err != nil {
					return nil, err
				}
				id := uint16(val)
				req.VideoStreamID = &id
			}
		case 3: // AudioStreamID
			if r.Type() == tlv.ElementTypeNull {
				empty := uint16(0)
				req.AudioStreamID = &empty
			} else {
				val, err := r.Uint()
				if err != nil {
					return nil, err
				}
				id := uint16(val)
				req.AudioStreamID = &id
			}
		case 4: // ICEServers
			req.ICEServers, _ = decodeICEServerList(r)
		case 5: // ICETransportPolicy
			req.ICETransportPolicy, _ = r.String()
		case 6: // MetadataEnabled
			req.MetadataEnabled, _ = r.Bool()
		case 7: // SFrameConfig
			// Skip for now
		}
	}

	_ = r.ExitContainer()
	return req, nil
}

func decodeProvideOffer(r *tlv.Reader) (*ProvideOfferRequest, error) {
	req := &ProvideOfferRequest{}

	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidTLV
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	for {
		if err := r.Next(); err != nil {
			return nil, err
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
			if r.Type() == tlv.ElementTypeNull {
				req.SessionID = nil
			} else {
				val, err := r.Uint()
				if err != nil {
					return nil, err
				}
				id := uint16(val)
				req.SessionID = &id
			}
		case 1: // SDP
			req.SDP, _ = r.String()
		case 2: // StreamUsage
			val, err := r.Uint()
			if err != nil {
				return nil, err
			}
			req.StreamUsage = StreamUsageEnum(val)
		case 3: // OriginatingEndpointID
			val, err := r.Uint()
			if err != nil {
				return nil, err
			}
			req.OriginatingEndpoint = uint16(val)
		case 4: // VideoStreamID
			if r.Type() == tlv.ElementTypeNull {
				empty := uint16(0)
				req.VideoStreamID = &empty
			} else {
				val, err := r.Uint()
				if err != nil {
					return nil, err
				}
				id := uint16(val)
				req.VideoStreamID = &id
			}
		case 5: // AudioStreamID
			if r.Type() == tlv.ElementTypeNull {
				empty := uint16(0)
				req.AudioStreamID = &empty
			} else {
				val, err := r.Uint()
				if err != nil {
					return nil, err
				}
				id := uint16(val)
				req.AudioStreamID = &id
			}
		case 6: // ICEServers
			req.ICEServers, _ = decodeICEServerList(r)
		case 7: // ICETransportPolicy
			req.ICETransportPolicy, _ = r.String()
		case 8: // MetadataEnabled
			req.MetadataEnabled, _ = r.Bool()
		case 9: // SFrameConfig
			// Skip for now
		}
	}

	_ = r.ExitContainer()
	return req, nil
}

func decodeProvideAnswer(r *tlv.Reader) (uint16, string, error) {
	var sessionID uint16
	var sdp string

	if err := r.Next(); err != nil {
		return 0, "", err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return 0, "", ErrInvalidTLV
	}
	if err := r.EnterContainer(); err != nil {
		return 0, "", err
	}

	for {
		if err := r.Next(); err != nil {
			return 0, "", err
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
			val, err := r.Uint()
			if err != nil {
				return 0, "", err
			}
			sessionID = uint16(val)
		case 1: // SDP
			sdp, _ = r.String()
		}
	}

	_ = r.ExitContainer()
	return sessionID, sdp, nil
}

func decodeProvideICECandidates(r *tlv.Reader) (uint16, []ICECandidateStruct, error) {
	var sessionID uint16
	var candidates []ICECandidateStruct

	if err := r.Next(); err != nil {
		return 0, nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return 0, nil, ErrInvalidTLV
	}
	if err := r.EnterContainer(); err != nil {
		return 0, nil, err
	}

	for {
		if err := r.Next(); err != nil {
			return 0, nil, err
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
			val, err := r.Uint()
			if err != nil {
				return 0, nil, err
			}
			sessionID = uint16(val)
		case 1: // ICECandidates
			candidates, _ = decodeICECandidateList(r)
		}
	}

	_ = r.ExitContainer()
	return sessionID, candidates, nil
}

func decodeEndSession(r *tlv.Reader) (uint16, WebRTCEndReasonEnum, error) {
	var sessionID uint16
	var reason WebRTCEndReasonEnum

	if err := r.Next(); err != nil {
		return 0, 0, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return 0, 0, ErrInvalidTLV
	}
	if err := r.EnterContainer(); err != nil {
		return 0, 0, err
	}

	for {
		if err := r.Next(); err != nil {
			return 0, 0, err
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
			val, err := r.Uint()
			if err != nil {
				return 0, 0, err
			}
			sessionID = uint16(val)
		case 1: // Reason
			val, err := r.Uint()
			if err != nil {
				return 0, 0, err
			}
			reason = WebRTCEndReasonEnum(val)
		}
	}

	_ = r.ExitContainer()
	return sessionID, reason, nil
}

func decodeICEServerList(r *tlv.Reader) ([]ICEServerStruct, error) {
	if r.Type() != tlv.ElementTypeArray {
		return nil, nil
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var servers []ICEServerStruct
	for {
		if err := r.Next(); err != nil {
			break
		}
		if r.Type() == tlv.ElementTypeEnd {
			break
		}
		// Each element is a struct - need to parse inline
		// For simplicity, skip detailed parsing
	}

	_ = r.ExitContainer()
	return servers, nil
}

func decodeICECandidateList(r *tlv.Reader) ([]ICECandidateStruct, error) {
	if r.Type() != tlv.ElementTypeArray {
		return nil, nil
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var candidates []ICECandidateStruct
	for {
		if err := r.Next(); err != nil {
			break
		}
		if r.Type() == tlv.ElementTypeEnd {
			break
		}
		if r.Type() != tlv.ElementTypeStruct {
			continue
		}
		if err := r.EnterContainer(); err != nil {
			continue
		}

		var c ICECandidateStruct
		for {
			if err := r.Next(); err != nil {
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
			case 0:
				c.Candidate, _ = r.String()
			case 1:
				if r.Type() != tlv.ElementTypeNull {
					s, _ := r.String()
					c.SDPMid = &s
				}
			case 2:
				if r.Type() != tlv.ElementTypeNull {
					v, _ := r.Uint()
					idx := uint16(v)
					c.SDPMLineIndex = &idx
				}
			}
		}
		_ = r.ExitContainer()
		candidates = append(candidates, c)
	}

	_ = r.ExitContainer()
	return candidates, nil
}

func encodeSolicitOfferResponse(sessionID uint16, deferredOffer bool, videoStreamID, audioStreamID *uint16) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutUint(tlv.ContextTag(0), uint64(sessionID)); err != nil {
		return nil, err
	}
	if err := w.PutBool(tlv.ContextTag(1), deferredOffer); err != nil {
		return nil, err
	}

	if videoStreamID != nil {
		if err := w.PutUint(tlv.ContextTag(2), uint64(*videoStreamID)); err != nil {
			return nil, err
		}
	} else {
		if err := w.PutNull(tlv.ContextTag(2)); err != nil {
			return nil, err
		}
	}

	if audioStreamID != nil {
		if err := w.PutUint(tlv.ContextTag(3), uint64(*audioStreamID)); err != nil {
			return nil, err
		}
	} else {
		if err := w.PutNull(tlv.ContextTag(3)); err != nil {
			return nil, err
		}
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func encodeProvideOfferResponse(sessionID uint16, videoStreamID, audioStreamID *uint16) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutUint(tlv.ContextTag(0), uint64(sessionID)); err != nil {
		return nil, err
	}

	if videoStreamID != nil {
		if err := w.PutUint(tlv.ContextTag(1), uint64(*videoStreamID)); err != nil {
			return nil, err
		}
	} else {
		if err := w.PutNull(tlv.ContextTag(1)); err != nil {
			return nil, err
		}
	}

	if audioStreamID != nil {
		if err := w.PutUint(tlv.ContextTag(2), uint64(*audioStreamID)); err != nil {
			return nil, err
		}
	} else {
		if err := w.PutNull(tlv.ContextTag(2)); err != nil {
			return nil, err
		}
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
