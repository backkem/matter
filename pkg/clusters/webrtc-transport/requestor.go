package webrtctransport

import (
	"context"
	"sync"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/tlv"
)

// RequestorConfig provides dependencies for the WebRTC Transport Requestor cluster.
type RequestorConfig struct {
	// EndpointID is the endpoint this cluster belongs to.
	EndpointID datamodel.EndpointID

	// Delegate handles WebRTC signaling events.
	Delegate RequestorDelegate
}

// Requestor implements the WebRTC Transport Requestor cluster (0x0554).
type Requestor struct {
	*datamodel.ClusterBase
	config RequestorConfig

	mu              sync.RWMutex
	sessions        map[uint16]*WebRTCSessionStruct // sessionID -> session
	currentSessions []WebRTCSessionStruct

	attrList []datamodel.AttributeEntry
}

// NewRequestor creates a new WebRTC Transport Requestor cluster.
func NewRequestor(cfg RequestorConfig) *Requestor {
	r := &Requestor{
		ClusterBase: datamodel.NewClusterBase(datamodel.ClusterID(RequestorClusterID), cfg.EndpointID, RequestorClusterRevision),
		config:      cfg,
		sessions:    make(map[uint16]*WebRTCSessionStruct),
	}

	r.attrList = r.buildAttributeList()
	return r
}

// buildAttributeList constructs the list of supported attributes.
func (r *Requestor) buildAttributeList() []datamodel.AttributeEntry {
	viewPriv := datamodel.PrivilegeView
	attrs := []datamodel.AttributeEntry{
		datamodel.NewReadOnlyAttribute(datamodel.AttributeID(AttrCurrentSessions), datamodel.AttrQualityFabricScoped, viewPriv),
	}
	return datamodel.MergeAttributeLists(attrs)
}

// AttributeList implements datamodel.Cluster.
func (r *Requestor) AttributeList() []datamodel.AttributeEntry {
	return r.attrList
}

// AcceptedCommandList implements datamodel.Cluster.
func (r *Requestor) AcceptedCommandList() []datamodel.CommandEntry {
	operatePriv := datamodel.PrivilegeOperate
	return []datamodel.CommandEntry{
		datamodel.NewCommandEntry(datamodel.CommandID(CmdOffer), 0, operatePriv),
		datamodel.NewCommandEntry(datamodel.CommandID(CmdAnswer), 0, operatePriv),
		datamodel.NewCommandEntry(datamodel.CommandID(CmdICECandidates), 0, operatePriv),
		datamodel.NewCommandEntry(datamodel.CommandID(CmdEnd), 0, operatePriv),
	}
}

// GeneratedCommandList implements datamodel.Cluster.
func (r *Requestor) GeneratedCommandList() []datamodel.CommandID {
	return nil // Requestor doesn't generate response commands
}

// ReadAttribute implements datamodel.Cluster.
func (r *Requestor) ReadAttribute(ctx context.Context, req datamodel.ReadAttributeRequest, w *tlv.Writer) error {
	handled, err := r.ReadGlobalAttribute(ctx, req.Path.Attribute, w,
		r.attrList, r.AcceptedCommandList(), r.GeneratedCommandList())
	if handled || err != nil {
		return err
	}

	switch req.Path.Attribute {
	case datamodel.AttributeID(AttrCurrentSessions):
		return r.readCurrentSessions(req.FabricIndex(), w)
	default:
		return datamodel.ErrUnsupportedAttribute
	}
}

// readCurrentSessions writes the CurrentSessions attribute filtered by fabric.
func (r *Requestor) readCurrentSessions(fabricIndex fabric.FabricIndex, w *tlv.Writer) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if err := w.StartArray(tlv.Anonymous()); err != nil {
		return err
	}

	for _, session := range r.sessions {
		if fabric.FabricIndex(session.FabricIndex) == fabricIndex {
			if err := session.MarshalTLV(w); err != nil {
				return err
			}
		}
	}

	return w.EndContainer()
}

// WriteAttribute implements datamodel.Cluster.
func (r *Requestor) WriteAttribute(ctx context.Context, req datamodel.WriteAttributeRequest, rd *tlv.Reader) error {
	return datamodel.ErrUnsupportedWrite
}

// InvokeCommand implements datamodel.Cluster.
func (r *Requestor) InvokeCommand(ctx context.Context, req datamodel.InvokeRequest, rd *tlv.Reader) ([]byte, error) {
	switch req.Path.Command {
	case datamodel.CommandID(CmdOffer):
		return r.handleOffer(ctx, req, rd)
	case datamodel.CommandID(CmdAnswer):
		return r.handleAnswer(ctx, req, rd)
	case datamodel.CommandID(CmdICECandidates):
		return r.handleICECandidates(ctx, req, rd)
	case datamodel.CommandID(CmdEnd):
		return r.handleEnd(ctx, req, rd)
	default:
		return nil, datamodel.ErrUnsupportedCommand
	}
}

// handleOffer handles the Offer command from the Provider.
func (r *Requestor) handleOffer(ctx context.Context, req datamodel.InvokeRequest, rd *tlv.Reader) ([]byte, error) {
	if r.config.Delegate == nil {
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
	sessionID, sdp, iceServers, iceTransportPolicy, err := decodeOffer(rd)
	if err != nil {
		return nil, err
	}

	// Lookup session
	r.mu.RLock()
	session := r.sessions[sessionID]
	r.mu.RUnlock()
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Verify peer
	if session.PeerNodeID != sourceNodeID || session.FabricIndex != fabricIndex {
		return nil, ErrUnauthorized
	}

	// Call delegate
	if err := r.config.Delegate.OnOffer(ctx, sessionID, sdp, iceServers, iceTransportPolicy); err != nil {
		return nil, err
	}

	return nil, nil // Status-only response
}

// handleAnswer handles the Answer command from the Provider.
func (r *Requestor) handleAnswer(ctx context.Context, req datamodel.InvokeRequest, rd *tlv.Reader) ([]byte, error) {
	if r.config.Delegate == nil {
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
	sessionID, sdp, err := decodeAnswer(rd)
	if err != nil {
		return nil, err
	}

	// Lookup session
	r.mu.RLock()
	session := r.sessions[sessionID]
	r.mu.RUnlock()
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Verify peer
	if session.PeerNodeID != sourceNodeID || session.FabricIndex != fabricIndex {
		return nil, ErrUnauthorized
	}

	// Call delegate
	if err := r.config.Delegate.OnAnswer(ctx, sessionID, sdp); err != nil {
		return nil, err
	}

	return nil, nil // Status-only response
}

// handleICECandidates handles the ICECandidates command from the Provider.
func (r *Requestor) handleICECandidates(ctx context.Context, req datamodel.InvokeRequest, rd *tlv.Reader) ([]byte, error) {
	if r.config.Delegate == nil {
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
	sessionID, candidates, err := decodeRequestorICECandidates(rd)
	if err != nil {
		return nil, err
	}

	// Lookup session
	r.mu.RLock()
	session := r.sessions[sessionID]
	r.mu.RUnlock()
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Verify peer
	if session.PeerNodeID != sourceNodeID || session.FabricIndex != fabricIndex {
		return nil, ErrUnauthorized
	}

	// Call delegate
	if err := r.config.Delegate.OnICECandidates(ctx, sessionID, candidates); err != nil {
		return nil, err
	}

	return nil, nil // Status-only response
}

// handleEnd handles the End command from the Provider.
func (r *Requestor) handleEnd(ctx context.Context, req datamodel.InvokeRequest, rd *tlv.Reader) ([]byte, error) {
	// Get subject info
	var sourceNodeID uint64
	var fabricIndex uint8
	if req.Subject != nil {
		sourceNodeID = req.Subject.NodeID
		fabricIndex = uint8(req.Subject.FabricIndex)
	}

	// Decode command fields
	sessionID, reason, err := decodeEnd(rd)
	if err != nil {
		return nil, err
	}

	// Lookup and remove session
	r.mu.Lock()
	session := r.sessions[sessionID]
	if session == nil {
		r.mu.Unlock()
		return nil, ErrSessionNotFound
	}

	// Verify peer
	if session.PeerNodeID != sourceNodeID || session.FabricIndex != fabricIndex {
		r.mu.Unlock()
		return nil, ErrUnauthorized
	}

	delete(r.sessions, sessionID)
	r.mu.Unlock()

	// Call delegate if set
	if r.config.Delegate != nil {
		_ = r.config.Delegate.OnEnd(ctx, sessionID, reason)
	}

	return nil, nil // Status-only response
}

// AddSession adds a session to the Requestor's session list.
// Called when the Requestor initiates a connection (after receiving ProvideOfferResponse).
func (r *Requestor) AddSession(session *WebRTCSessionStruct) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[session.ID] = session
}

// GetSession returns a session by ID.
func (r *Requestor) GetSession(sessionID uint16) *WebRTCSessionStruct {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[sessionID]
}

// RemoveSession removes a session by ID.
func (r *Requestor) RemoveSession(sessionID uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, sessionID)
}

// --- TLV Decoding Helpers ---

func decodeOffer(r *tlv.Reader) (uint16, string, []ICEServerStruct, string, error) {
	var sessionID uint16
	var sdp string
	var iceServers []ICEServerStruct
	var iceTransportPolicy string

	if err := r.Next(); err != nil {
		return 0, "", nil, "", err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return 0, "", nil, "", ErrInvalidTLV
	}
	if err := r.EnterContainer(); err != nil {
		return 0, "", nil, "", err
	}

	for {
		if err := r.Next(); err != nil {
			return 0, "", nil, "", err
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
				return 0, "", nil, "", err
			}
			sessionID = uint16(val)
		case 1: // SDP
			sdp, _ = r.String()
		case 2: // ICEServers
			iceServers, _ = decodeICEServerList(r)
		case 3: // ICETransportPolicy
			iceTransportPolicy, _ = r.String()
		}
	}

	_ = r.ExitContainer()
	return sessionID, sdp, iceServers, iceTransportPolicy, nil
}

func decodeAnswer(r *tlv.Reader) (uint16, string, error) {
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

func decodeRequestorICECandidates(r *tlv.Reader) (uint16, []ICECandidateStruct, error) {
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

func decodeEnd(r *tlv.Reader) (uint16, WebRTCEndReasonEnum, error) {
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
