// Package securechannel implements the Matter Secure Channel Protocol.
//
// The Manager coordinates session establishment via PASE and CASE,
// routes messages by opcode, and handles unsolicited status reports.
//
// See Matter Specification Section 4.11.

package securechannel

import (
	"errors"
	"sync"
	"time"

	"github.com/backkem/matter/pkg/crypto"
	"github.com/backkem/matter/pkg/fabric"
	casesession "github.com/backkem/matter/pkg/securechannel/case"
	"github.com/backkem/matter/pkg/securechannel/pase"
	"github.com/backkem/matter/pkg/session"
)

// Constants for secure channel manager.
const (
	// DefaultBusyWaitTime is the default wait time in milliseconds for Busy responses.
	DefaultBusyWaitTime = 5000

	// HandshakeTimeout is the maximum duration for a handshake to complete.
	HandshakeTimeout = 60 * time.Second
)

// Errors returned by the Manager.
var (
	ErrNoHandler           = errors.New("securechannel: no handler for message type")
	ErrHandshakeInProgress = errors.New("securechannel: handshake already in progress")
	ErrNoActiveHandshake   = errors.New("securechannel: no active handshake")
	ErrSessionTableFull    = errors.New("securechannel: session table full")
	ErrInvalidOpcode       = errors.New("securechannel: invalid opcode for current state")
	ErrSessionClosed       = errors.New("securechannel: session closed by peer")
)

// Message represents a secure channel protocol message (request or response).
// It pairs an opcode with its payload for symmetric handling.
type Message struct {
	Opcode  Opcode
	Payload []byte
}

// NewMessage creates a new Message. Returns nil if payload is nil.
func NewMessage(opcode Opcode, payload []byte) *Message {
	if payload == nil {
		return nil
	}
	return &Message{Opcode: opcode, Payload: payload}
}

// HandshakeType indicates the type of secure session being established.
type HandshakeType int

const (
	HandshakeTypePASE HandshakeType = iota
	HandshakeTypeCASE
)

// String returns the handshake type name.
func (h HandshakeType) String() string {
	switch h {
	case HandshakeTypePASE:
		return "PASE"
	case HandshakeTypeCASE:
		return "CASE"
	default:
		return "Unknown"
	}
}

// Callbacks provides callback functions for Manager events.
type Callbacks struct {
	// OnSessionEstablished is called when a session is successfully established.
	// The callback receives the new secure context.
	OnSessionEstablished func(ctx *session.SecureContext)

	// OnSessionError is called when session establishment fails.
	// The callback receives the error and the stage at which it occurred.
	OnSessionError func(err error, stage string)

	// OnSessionClosed is called when a peer closes a session via CloseSession.
	// The callback receives the closed session's local ID.
	OnSessionClosed func(localSessionID uint16)

	// OnResponderBusy is called when a responder sends a Busy status.
	// The callback receives the minimum wait time in milliseconds.
	OnResponderBusy func(waitTimeMs uint16)
}

// ManagerConfig configures the secure channel Manager.
type ManagerConfig struct {
	// SessionManager manages secure session contexts.
	SessionManager *session.Manager

	// FabricTable provides fabric lookup for CASE.
	FabricTable *fabric.Table

	// CertValidator validates peer certificate chains during CASE.
	// If nil, certificate validation is skipped (testing only).
	CertValidator casesession.ValidatePeerCertChainFunc

	// Callbacks for Manager events.
	Callbacks Callbacks

	// LocalNodeID is our operational node ID (0 for uncommissioned).
	LocalNodeID fabric.NodeID
}

// handshakeContext tracks an active handshake.
type handshakeContext struct {
	handshakeType   HandshakeType
	paseSession     *pase.Session
	caseSession     *casesession.Session
	localSessionID  uint16
	peerSessionID   uint16
	startTime       time.Time
	pinnedSessionID uint16 // Pre-allocated session ID to prevent eviction
}

// paseResponderConfig holds PASE responder configuration.
type paseResponderConfig struct {
	verifier   *pase.Verifier
	salt       []byte
	iterations uint32
}

// Manager coordinates secure channel protocol operations.
type Manager struct {
	config ManagerConfig

	// Active handshakes keyed by exchange ID
	handshakes map[uint16]*handshakeContext

	// PASE responder configuration (set when commissioning window is open)
	paseResponder *paseResponderConfig

	mu sync.RWMutex
}

// NewManager creates a new secure channel Manager.
func NewManager(config ManagerConfig) *Manager {
	return &Manager{
		config:     config,
		handshakes: make(map[uint16]*handshakeContext),
	}
}

// MessagePermitted returns true if the opcode is allowed during session establishment.
// This implements the SessionEstablishmentExchangeDispatch whitelist from the C reference.
func MessagePermitted(opcode Opcode) bool {
	switch opcode {
	case OpcodePBKDFParamRequest, OpcodePBKDFParamResponse,
		OpcodePASEPake1, OpcodePASEPake2, OpcodePASEPake3,
		OpcodeCASESigma1, OpcodeCASESigma2, OpcodeCASESigma3, OpcodeCASESigma2Resume,
		OpcodeStandaloneAck, OpcodeStatusReport:
		return true
	default:
		return false
	}
}

// IsPASEOpcode returns true if the opcode is for PASE protocol.
func IsPASEOpcode(opcode Opcode) bool {
	switch opcode {
	case OpcodePBKDFParamRequest, OpcodePBKDFParamResponse,
		OpcodePASEPake1, OpcodePASEPake2, OpcodePASEPake3:
		return true
	default:
		return false
	}
}

// IsCASEOpcode returns true if the opcode is for CASE protocol.
func IsCASEOpcode(opcode Opcode) bool {
	switch opcode {
	case OpcodeCASESigma1, OpcodeCASESigma2, OpcodeCASESigma3, OpcodeCASESigma2Resume:
		return true
	default:
		return false
	}
}

// Route dispatches an incoming message to the appropriate handler.
// Returns the response message (opcode + payload) if any, and an error.
func (m *Manager) Route(exchangeID uint16, msg *Message) (*Message, error) {
	if msg == nil {
		return nil, ErrInvalidOpcode
	}
	if !MessagePermitted(msg.Opcode) {
		return nil, ErrInvalidOpcode
	}

	switch {
	case IsPASEOpcode(msg.Opcode):
		return m.handlePASE(exchangeID, msg.Opcode, msg.Payload)
	case IsCASEOpcode(msg.Opcode):
		return m.handleCASE(exchangeID, msg.Opcode, msg.Payload)
	case msg.Opcode == OpcodeStatusReport:
		return m.handleStatusReport(exchangeID, msg.Payload)
	case msg.Opcode == OpcodeStandaloneAck:
		// Standalone ACK - no response needed, handled by MRP layer
		return nil, nil
	default:
		return nil, ErrNoHandler
	}
}

// handlePASE routes PASE protocol messages.
func (m *Manager) handlePASE(exchangeID uint16, opcode Opcode, payload []byte) (*Message, error) {
	resp, secureCtx, err := m.handlePASELocked(exchangeID, opcode, payload)
	if err != nil {
		return nil, err
	}

	// Notify callback outside lock to prevent deadlocks
	if secureCtx != nil && m.config.Callbacks.OnSessionEstablished != nil {
		m.config.Callbacks.OnSessionEstablished(secureCtx)
	}

	return resp, nil
}

// handlePASELocked handles PASE messages under lock.
// Returns response, established session (if any), and error.
func (m *Manager) handlePASELocked(exchangeID uint16, opcode Opcode, payload []byte) (*Message, *session.SecureContext, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, exists := m.handshakes[exchangeID]

	switch opcode {
	case OpcodePBKDFParamRequest:
		// New PASE handshake as responder
		if exists {
			// Already have a handshake on this exchange - send busy
			resp, err := m.sendBusyResponse(ctx)
			return resp, nil, err
		}
		resp, err := m.handlePBKDFParamRequest(exchangeID, payload)
		return resp, nil, err

	case OpcodePBKDFParamResponse:
		if !exists || ctx.handshakeType != HandshakeTypePASE || ctx.paseSession == nil {
			return nil, nil, ErrNoActiveHandshake
		}
		resp, err := m.handlePBKDFParamResponse(ctx, payload)
		return resp, nil, err

	case OpcodePASEPake1:
		if !exists || ctx.handshakeType != HandshakeTypePASE || ctx.paseSession == nil {
			return nil, nil, ErrNoActiveHandshake
		}
		resp, err := m.handlePake1(ctx, payload)
		return resp, nil, err

	case OpcodePASEPake2:
		if !exists || ctx.handshakeType != HandshakeTypePASE || ctx.paseSession == nil {
			return nil, nil, ErrNoActiveHandshake
		}
		resp, err := m.handlePake2(ctx, payload)
		return resp, nil, err

	case OpcodePASEPake3:
		if !exists || ctx.handshakeType != HandshakeTypePASE || ctx.paseSession == nil {
			return nil, nil, ErrNoActiveHandshake
		}
		resp, needsComplete, err := m.handlePake3(exchangeID, ctx, payload)
		if err != nil {
			return nil, nil, err
		}
		if needsComplete {
			secureCtx, completeErr := m.completeHandshakeLocked(exchangeID, ctx)
			if completeErr != nil {
				return nil, nil, completeErr
			}
			return resp, secureCtx, nil
		}
		return resp, nil, nil

	default:
		return nil, nil, ErrInvalidOpcode
	}
}

// handleCASE routes CASE protocol messages.
func (m *Manager) handleCASE(exchangeID uint16, opcode Opcode, payload []byte) (*Message, error) {
	resp, secureCtx, err := m.handleCASELocked(exchangeID, opcode, payload)
	if err != nil {
		return nil, err
	}

	// Notify callback outside lock to prevent deadlocks
	if secureCtx != nil && m.config.Callbacks.OnSessionEstablished != nil {
		m.config.Callbacks.OnSessionEstablished(secureCtx)
	}

	return resp, nil
}

// handleCASELocked handles CASE messages under lock.
// Returns response, established session (if any), and error.
func (m *Manager) handleCASELocked(exchangeID uint16, opcode Opcode, payload []byte) (*Message, *session.SecureContext, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, exists := m.handshakes[exchangeID]

	switch opcode {
	case OpcodeCASESigma1:
		// New CASE handshake as responder
		if exists {
			// Already have a handshake on this exchange - send busy
			resp, err := m.sendBusyResponse(ctx)
			return resp, nil, err
		}
		resp, err := m.handleSigma1(exchangeID, payload)
		return resp, nil, err

	case OpcodeCASESigma2, OpcodeCASESigma2Resume:
		if !exists || ctx.handshakeType != HandshakeTypeCASE || ctx.caseSession == nil {
			return nil, nil, ErrNoActiveHandshake
		}
		resp, err := m.handleSigma2(ctx, opcode, payload)
		return resp, nil, err

	case OpcodeCASESigma3:
		if !exists || ctx.handshakeType != HandshakeTypeCASE || ctx.caseSession == nil {
			return nil, nil, ErrNoActiveHandshake
		}
		resp, needsComplete, err := m.handleSigma3(exchangeID, ctx, payload)
		if err != nil {
			return nil, nil, err
		}
		if needsComplete {
			secureCtx, completeErr := m.completeHandshakeLocked(exchangeID, ctx)
			if completeErr != nil {
				return nil, nil, completeErr
			}
			return resp, secureCtx, nil
		}
		return resp, nil, nil

	default:
		return nil, nil, ErrInvalidOpcode
	}
}

// handleStatusReport processes an incoming StatusReport.
func (m *Manager) handleStatusReport(exchangeID uint16, payload []byte) (*Message, error) {
	status, err := DecodeStatusReport(payload)
	if err != nil {
		return nil, err
	}

	// Check if this is a Busy response
	if status.IsBusy() {
		waitTime := status.BusyWaitTime()
		if m.config.Callbacks.OnResponderBusy != nil {
			m.config.Callbacks.OnResponderBusy(waitTime)
		}
		// Clean up the handshake
		m.cleanupHandshake(exchangeID)
		return nil, nil
	}

	// Check for session establishment success
	if status.IsSuccess() && status.IsSecureChannel() &&
		status.SecureChannelCode() == ProtocolCodeSuccess {
		secureCtx, err := m.handleStatusReportSuccess(exchangeID)
		if err != nil {
			return nil, err
		}
		// Notify callback outside lock
		if secureCtx != nil && m.config.Callbacks.OnSessionEstablished != nil {
			m.config.Callbacks.OnSessionEstablished(secureCtx)
		}
		return nil, nil
	}

	// Check for CloseSession
	if status.IsSuccess() && status.IsSecureChannel() &&
		status.SecureChannelCode() == ProtocolCodeCloseSession {
		// This should be handled on secure sessions, not during handshake
		return nil, ErrSessionClosed
	}

	// Error status during handshake
	m.mu.Lock()
	ctx, exists := m.handshakes[exchangeID]
	m.mu.Unlock()
	if exists && !status.IsSuccess() {
		m.cleanupHandshake(exchangeID)
		if m.config.Callbacks.OnSessionError != nil {
			m.config.Callbacks.OnSessionError(status, "StatusReport")
		}
	}
	_ = ctx // ctx used for exists check

	return nil, nil
}

// handleStatusReportSuccess handles successful status report under lock.
func (m *Manager) handleStatusReportSuccess(exchangeID uint16) (*session.SecureContext, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, exists := m.handshakes[exchangeID]
	if !exists {
		return nil, nil
	}

	return m.completeHandshakeLocked(exchangeID, ctx)
}

// sendBusyResponse creates a Busy StatusReport response.
func (m *Manager) sendBusyResponse(ctx *handshakeContext) (*Message, error) {
	var waitTimeMs uint16 = DefaultBusyWaitTime

	// Calculate wait time based on handshake state
	if ctx != nil && ctx.caseSession != nil {
		state := ctx.caseSession.State()
		if state == casesession.StateWaitingSigma3 {
			// If we sent Sigma2, give time for Sigma3
			waitTimeMs = 10000
		}
	}

	return NewMessage(OpcodeStatusReport, Busy(waitTimeMs).Encode()), nil
}

// cleanupHandshake removes a handshake context.
func (m *Manager) cleanupHandshake(exchangeID uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.handshakes, exchangeID)
}

// cleanupHandshakeLocked removes a handshake context. Caller must hold m.mu.
func (m *Manager) cleanupHandshakeLocked(exchangeID uint16) {
	delete(m.handshakes, exchangeID)
}

// StartPASE begins a PASE handshake as initiator.
// Returns the PBKDFParamRequest message to send.
func (m *Manager) StartPASE(exchangeID uint16, passcode uint32) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if we already have a handshake on this exchange
	if _, exists := m.handshakes[exchangeID]; exists {
		return nil, ErrHandshakeInProgress
	}

	// Allocate session ID
	localSessionID, err := m.config.SessionManager.AllocateSessionID()
	if err != nil {
		return nil, ErrSessionTableFull
	}

	// Create PASE session
	paseSession, err := pase.NewInitiator(passcode)
	if err != nil {
		return nil, err
	}

	// Start the handshake
	pbkdfReq, err := paseSession.Start(localSessionID)
	if err != nil {
		return nil, err
	}

	// Track the handshake
	m.handshakes[exchangeID] = &handshakeContext{
		handshakeType:  HandshakeTypePASE,
		paseSession:    paseSession,
		localSessionID: localSessionID,
		startTime:      time.Now(),
	}

	return pbkdfReq, nil
}

// StartCASE begins a CASE handshake as initiator.
// Returns the Sigma1 message to send.
func (m *Manager) StartCASE(
	exchangeID uint16,
	fabricInfo *fabric.FabricInfo,
	operationalKey *crypto.P256KeyPair,
	targetNodeID uint64,
	resumptionInfo *casesession.ResumptionInfo,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if we already have a handshake on this exchange
	if _, exists := m.handshakes[exchangeID]; exists {
		return nil, ErrHandshakeInProgress
	}

	// Allocate session ID
	localSessionID, err := m.config.SessionManager.AllocateSessionID()
	if err != nil {
		return nil, ErrSessionTableFull
	}

	// Create CASE session
	caseSession := casesession.NewInitiator(fabricInfo, operationalKey, targetNodeID)

	// Add certificate validator
	if m.config.CertValidator != nil {
		caseSession.WithCertValidator(m.config.CertValidator)
	}

	// Add resumption info if provided
	if resumptionInfo != nil {
		caseSession.WithResumption(resumptionInfo)
	}

	// Start the handshake
	sigma1, err := caseSession.Start(localSessionID)
	if err != nil {
		return nil, err
	}

	// Track the handshake
	m.handshakes[exchangeID] = &handshakeContext{
		handshakeType:  HandshakeTypeCASE,
		caseSession:    caseSession,
		localSessionID: localSessionID,
		startTime:      time.Now(),
	}

	return sigma1, nil
}

// handlePBKDFParamRequest handles an incoming PBKDFParamRequest (responder).
func (m *Manager) handlePBKDFParamRequest(exchangeID uint16, payload []byte) (*Message, error) {
	// Check if PASE responder is configured
	if m.paseResponder == nil {
		return nil, errors.New("securechannel: PASE responder not configured (commissioning window not open)")
	}

	// Allocate session ID
	localSessionID, err := m.config.SessionManager.AllocateSessionID()
	if err != nil {
		return nil, ErrSessionTableFull
	}

	// Create PASE session as responder
	paseSession, err := pase.NewResponder(
		m.paseResponder.verifier,
		m.paseResponder.salt,
		m.paseResponder.iterations,
	)
	if err != nil {
		return nil, err
	}

	// Handle the PBKDFParamRequest and get response
	pbkdfResp, err := paseSession.HandlePBKDFParamRequest(payload, localSessionID)
	if err != nil {
		return nil, err
	}

	// Store peer session ID from the request
	peerSessionID := paseSession.PeerSessionID()

	// Track the handshake
	m.handshakes[exchangeID] = &handshakeContext{
		handshakeType:  HandshakeTypePASE,
		paseSession:    paseSession,
		localSessionID: localSessionID,
		peerSessionID:  peerSessionID,
		startTime:      time.Now(),
	}

	return NewMessage(OpcodePBKDFParamResponse, pbkdfResp), nil
}

// SetPASEResponder configures the Manager to respond to PASE requests.
// This must be called before receiving PBKDFParamRequest messages.
// Call ClearPASEResponder when the commissioning window closes.
func (m *Manager) SetPASEResponder(verifier *pase.Verifier, salt []byte, iterations uint32) error {
	if verifier == nil {
		return errors.New("securechannel: verifier is nil")
	}
	if len(salt) < pase.PBKDFMinSaltLength || len(salt) > pase.PBKDFMaxSaltLength {
		return errors.New("securechannel: invalid salt length")
	}
	if iterations < pase.PBKDFMinIterations || iterations > pase.PBKDFMaxIterations {
		return errors.New("securechannel: invalid iteration count")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.paseResponder = &paseResponderConfig{
		verifier:   verifier,
		salt:       salt,
		iterations: iterations,
	}
	return nil
}

// ClearPASEResponder clears the PASE responder configuration.
// Call this when the commissioning window closes.
func (m *Manager) ClearPASEResponder() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paseResponder = nil
}

// HasPASEResponder returns true if PASE responder is configured.
func (m *Manager) HasPASEResponder() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.paseResponder != nil
}

// handlePBKDFParamResponse handles PBKDFParamResponse (initiator).
func (m *Manager) handlePBKDFParamResponse(ctx *handshakeContext, payload []byte) (*Message, error) {
	pake1, err := ctx.paseSession.HandlePBKDFParamResponse(payload)
	if err != nil {
		return nil, err
	}
	return NewMessage(OpcodePASEPake1, pake1), nil
}

// handlePake1 handles Pake1 message (responder).
func (m *Manager) handlePake1(ctx *handshakeContext, payload []byte) (*Message, error) {
	pake2, err := ctx.paseSession.HandlePake1(payload)
	if err != nil {
		return nil, err
	}
	return NewMessage(OpcodePASEPake2, pake2), nil
}

// handlePake2 handles Pake2 message (initiator).
func (m *Manager) handlePake2(ctx *handshakeContext, payload []byte) (*Message, error) {
	pake3, err := ctx.paseSession.HandlePake2(payload)
	if err != nil {
		return nil, err
	}
	return NewMessage(OpcodePASEPake3, pake3), nil
}

// handlePake3 handles Pake3 message (responder).
// Returns the response message and a flag indicating if handshake should be completed.
func (m *Manager) handlePake3(exchangeID uint16, ctx *handshakeContext, payload []byte) (*Message, bool, error) {
	_, success, err := ctx.paseSession.HandlePake3(payload)
	if err != nil {
		return nil, false, err
	}

	if !success {
		return nil, false, errors.New("securechannel: PASE confirmation failed")
	}

	// Signal completion needed
	needsComplete := ctx.paseSession.State() == pase.StateComplete

	// Return success StatusReport
	return NewMessage(OpcodeStatusReport, Success().Encode()), needsComplete, nil
}

// handleSigma1 handles an incoming Sigma1 (responder).
func (m *Manager) handleSigma1(exchangeID uint16, payload []byte) (*Message, error) {
	// Allocate session ID
	localSessionID, err := m.config.SessionManager.AllocateSessionID()
	if err != nil {
		return nil, ErrSessionTableFull
	}

	// Create fabric lookup function
	fabricLookup := m.createFabricLookupFunc()

	// Create resumption lookup function
	resumptionLookup := m.createResumptionLookupFunc()

	// Create CASE session as responder
	caseSession := casesession.NewResponder(fabricLookup, resumptionLookup)

	// Add certificate validator
	if m.config.CertValidator != nil {
		caseSession.WithCertValidator(m.config.CertValidator)
	}

	// Handle Sigma1 (returns response, isResumption flag, error)
	sigma2, isResumption, err := caseSession.HandleSigma1(payload, localSessionID)
	if err != nil {
		return nil, err
	}

	// Track the handshake
	m.handshakes[exchangeID] = &handshakeContext{
		handshakeType:  HandshakeTypeCASE,
		caseSession:    caseSession,
		localSessionID: localSessionID,
		startTime:      time.Now(),
	}

	// Return appropriate opcode based on resumption
	if isResumption {
		return NewMessage(OpcodeCASESigma2Resume, sigma2), nil
	}
	return NewMessage(OpcodeCASESigma2, sigma2), nil
}

// handleSigma2 handles Sigma2 or Sigma2Resume (initiator).
func (m *Manager) handleSigma2(ctx *handshakeContext, opcode Opcode, payload []byte) (*Message, error) {
	if opcode == OpcodeCASESigma2Resume {
		// HandleSigma2Resume returns only error (session completes with status report)
		err := ctx.caseSession.HandleSigma2Resume(payload)
		if err != nil {
			return nil, err
		}
		// For resumption, no Sigma3 is sent - just wait for StatusReport
		return nil, nil
	}

	// HandleSigma2 returns Sigma3 response
	sigma3, err := ctx.caseSession.HandleSigma2(payload)
	if err != nil {
		return nil, err
	}

	return NewMessage(OpcodeCASESigma3, sigma3), nil
}

// handleSigma3 handles Sigma3 (responder).
// Returns the response message and a flag indicating if handshake should be completed.
func (m *Manager) handleSigma3(exchangeID uint16, ctx *handshakeContext, payload []byte) (*Message, bool, error) {
	// HandleSigma3 returns only error
	err := ctx.caseSession.HandleSigma3(payload)
	if err != nil {
		return nil, false, err
	}

	// Signal completion needed
	needsComplete := ctx.caseSession.State() == casesession.StateComplete

	// Return success StatusReport
	return NewMessage(OpcodeStatusReport, Success().Encode()), needsComplete, nil
}

// completeHandshakeLocked creates the secure session context.
// Caller must hold m.mu. Returns the secure context for callback notification.
func (m *Manager) completeHandshakeLocked(exchangeID uint16, ctx *handshakeContext) (*session.SecureContext, error) {
	var secureCtx *session.SecureContext
	var err error

	switch ctx.handshakeType {
	case HandshakeTypePASE:
		secureCtx, err = m.completePASESession(ctx)
	case HandshakeTypeCASE:
		secureCtx, err = m.completeCASESession(ctx)
	}

	if err != nil {
		if m.config.Callbacks.OnSessionError != nil {
			m.config.Callbacks.OnSessionError(err, "CompleteHandshake")
		}
		m.cleanupHandshakeLocked(exchangeID)
		return nil, err
	}

	// Add to session manager
	if err := m.config.SessionManager.AddSecureContext(secureCtx); err != nil {
		if m.config.Callbacks.OnSessionError != nil {
			m.config.Callbacks.OnSessionError(err, "AddSecureContext")
		}
		m.cleanupHandshakeLocked(exchangeID)
		return nil, err
	}

	// Clean up handshake tracking
	m.cleanupHandshakeLocked(exchangeID)

	// Return secure context for callback notification (done outside lock by caller)
	return secureCtx, nil
}

// completePASESession creates a SecureContext from a completed PASE session.
func (m *Manager) completePASESession(ctx *handshakeContext) (*session.SecureContext, error) {
	// For initiator: process the status report to complete the session and derive keys
	if ctx.paseSession.Role() == pase.RoleInitiator &&
		ctx.paseSession.State() == pase.StateWaitingStatusReport {
		if err := ctx.paseSession.HandleStatusReport(true); err != nil {
			return nil, err
		}
	}

	keys := ctx.paseSession.SessionKeys()
	if keys == nil {
		return nil, errors.New("securechannel: PASE session keys not ready")
	}

	role := session.SessionRoleInitiator
	if ctx.paseSession.Role() == pase.RoleResponder {
		role = session.SessionRoleResponder
	}

	config := session.SecureContextConfig{
		SessionType:    session.SessionTypePASE,
		Role:           role,
		LocalSessionID: ctx.localSessionID,
		PeerSessionID:  ctx.peerSessionID,
		I2RKey:         keys.I2RKey[:],
		R2IKey:         keys.R2IKey[:],
		FabricIndex:    0, // PASE sessions have no fabric initially
		PeerNodeID:     0, // PASE sessions have unspecified node ID
		LocalNodeID:    0, // PASE sessions have unspecified node ID
	}

	return session.NewSecureContext(config)
}

// completeCASESession creates a SecureContext from a completed CASE session.
func (m *Manager) completeCASESession(ctx *handshakeContext) (*session.SecureContext, error) {
	// For initiator: process the status report to complete the session and derive keys
	if ctx.caseSession.Role() == casesession.RoleInitiator &&
		ctx.caseSession.State() == casesession.StateWaitingStatusReport {
		if err := ctx.caseSession.HandleStatusReport(true); err != nil {
			return nil, err
		}
	}

	keys, err := ctx.caseSession.SessionKeys()
	if err != nil {
		return nil, err
	}
	if keys == nil {
		return nil, errors.New("securechannel: CASE session keys not ready")
	}

	role := session.SessionRoleInitiator
	if ctx.caseSession.Role() == casesession.RoleResponder {
		role = session.SessionRoleResponder
	}

	// Get peer info from CASE session
	peerNodeID := ctx.caseSession.PeerNodeID()
	fabricIndex := fabric.FabricIndex(ctx.caseSession.FabricIndex())

	config := session.SecureContextConfig{
		SessionType:    session.SessionTypeCASE,
		Role:           role,
		LocalSessionID: ctx.localSessionID,
		PeerSessionID:  ctx.peerSessionID,
		I2RKey:         keys.I2RKey[:],
		R2IKey:         keys.R2IKey[:],
		SharedSecret:   ctx.caseSession.SharedSecret(),
		FabricIndex:    fabricIndex,
		PeerNodeID:     fabric.NodeID(peerNodeID),
		LocalNodeID:    m.config.LocalNodeID,
		CaseAuthTags:   ctx.caseSession.PeerCATs(),
	}

	secureCtx, err := session.NewSecureContext(config)
	if err != nil {
		return nil, err
	}

	// Set resumption ID for future session resumption
	resumptionID := ctx.caseSession.ResumptionID()
	secureCtx.SetResumptionID(resumptionID)

	return secureCtx, nil
}

// createFabricLookupFunc creates a fabric lookup function for CASE responder.
func (m *Manager) createFabricLookupFunc() casesession.FabricLookupFunc {
	return func(destinationID [casesession.DestinationIDSize]byte, initiatorRandom [casesession.RandomSize]byte) (*fabric.FabricInfo, *crypto.P256KeyPair, error) {
		if m.config.FabricTable == nil {
			return nil, nil, errors.New("securechannel: no fabric table configured")
		}

		// Iterate fabrics and find one that matches the destination ID
		var matchedFabric *fabric.FabricInfo
		_ = m.config.FabricTable.ForEach(func(info *fabric.FabricInfo) error {
			// Compute expected destination ID for this fabric
			// destinationID = HMAC-SHA256(key=IPK, msg=initiatorRandom || rootPubKey || fabricID || nodeID)
			// For now, this is a placeholder - full implementation needs to derive IPK and compute
			matchedFabric = info
			return errors.New("stop") // Stop at first match for now
		})

		if matchedFabric == nil {
			return nil, nil, casesession.ErrNoSharedRoot
		}

		// Return the fabric info - operational key would need to be stored/retrieved separately
		return matchedFabric, nil, nil
	}
}

// createResumptionLookupFunc creates a resumption lookup function for CASE responder.
func (m *Manager) createResumptionLookupFunc() casesession.ResumptionLookupFunc {
	return func(resumptionID [casesession.ResumptionIDSize]byte) ([]byte, *fabric.FabricInfo, *crypto.P256KeyPair, bool) {
		// Look up previous session by resumption ID
		// This requires access to stored resumption state
		// For now, return not found
		return nil, nil, nil, false
	}
}

// HasActiveHandshake returns true if there's an active handshake on the exchange.
func (m *Manager) HasActiveHandshake(exchangeID uint16) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.handshakes[exchangeID]
	return exists
}

// GetHandshakeType returns the type of handshake on the exchange, if any.
func (m *Manager) GetHandshakeType(exchangeID uint16) (HandshakeType, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ctx, exists := m.handshakes[exchangeID]
	if !exists {
		return 0, false
	}
	return ctx.handshakeType, true
}

// CleanupExpiredHandshakes removes handshakes that have timed out.
func (m *Manager) CleanupExpiredHandshakes() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for exchangeID, ctx := range m.handshakes {
		if now.Sub(ctx.startTime) > HandshakeTimeout {
			delete(m.handshakes, exchangeID)
			if m.config.Callbacks.OnSessionError != nil {
				m.config.Callbacks.OnSessionError(errors.New("handshake timeout"), "Timeout")
			}
		}
	}
}

// ActiveHandshakeCount returns the number of active handshakes.
func (m *Manager) ActiveHandshakeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.handshakes)
}
