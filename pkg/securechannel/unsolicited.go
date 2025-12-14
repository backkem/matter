package securechannel

import (
	"github.com/backkem/matter/pkg/session"
)

// UnsolicitedHandler handles unsolicited status reports on secure sessions.
// This includes CloseSession messages from peers indicating session termination.
//
// See Matter Specification Section 4.11.1.4 (CloseSession) and 4.11.1.5 (Busy).
type UnsolicitedHandler struct {
	sessionManager *session.Manager
	callbacks      Callbacks
}

// NewUnsolicitedHandler creates a new unsolicited status handler.
func NewUnsolicitedHandler(sessionManager *session.Manager, callbacks Callbacks) *UnsolicitedHandler {
	return &UnsolicitedHandler{
		sessionManager: sessionManager,
		callbacks:      callbacks,
	}
}

// HandleStatusReport processes an unsolicited StatusReport received on a secure session.
// Returns true if the status report was handled, false if it should be passed to upper layers.
func (h *UnsolicitedHandler) HandleStatusReport(localSessionID uint16, status *StatusReport) bool {
	// Only process secure channel status reports
	if !status.IsSecureChannel() {
		return false
	}

	switch status.SecureChannelCode() {
	case ProtocolCodeCloseSession:
		return h.handleCloseSession(localSessionID, status)
	case ProtocolCodeBusy:
		return h.handleBusy(status)
	default:
		return false
	}
}

// handleCloseSession processes a CloseSession status report.
// Per Section 4.11.1.4:
//   - CloseSession SHALL only be sent encrypted within a PASE or CASE session
//   - Upon receiving CloseSession, remove all state associated with the session
//   - The node MAY save state necessary for Session Resumption
func (h *UnsolicitedHandler) handleCloseSession(localSessionID uint16, status *StatusReport) bool {
	// Validate: must be SUCCESS general code
	if status.GeneralCode != GeneralCodeSuccess {
		return false
	}

	// Find and remove the session
	ctx := h.sessionManager.FindSecureContext(localSessionID)
	if ctx == nil {
		// Session not found - maybe already removed
		return true
	}

	// Mark session for eviction (asynchronous cleanup)
	// The session manager will handle zeroizing keys
	h.sessionManager.RemoveSecureContext(localSessionID)

	// Notify callback
	if h.callbacks.OnSessionClosed != nil {
		h.callbacks.OnSessionClosed(localSessionID)
	}

	return true
}

// handleBusy processes a Busy status report.
// Per Section 4.11.1.5:
//   - Busy indicates the responder cannot currently fulfill the request
//   - Contains minimum wait time in milliseconds before retrying
func (h *UnsolicitedHandler) handleBusy(status *StatusReport) bool {
	// Validate: must be BUSY general code
	if status.GeneralCode != GeneralCodeBusy {
		return false
	}

	// Extract wait time
	waitTime := status.BusyWaitTime()

	// Notify callback
	if h.callbacks.OnResponderBusy != nil {
		h.callbacks.OnResponderBusy(waitTime)
	}

	return true
}

// SendCloseSession creates a CloseSession message to send to a peer.
// This should be sent when:
//   - The interaction between nodes is complete
//   - The node needs to free up resources for a new session
//   - Fabric configuration associated with the session was removed
//
// The returned bytes should be sent over the secure session before removing it.
func SendCloseSession() []byte {
	return CloseSession().Encode()
}

// SendBusy creates a Busy status report to send to a peer.
// waitTimeMs is the minimum time in milliseconds the peer should wait before retrying.
//
// Per Section 4.11.1.5:
//   - SHALL NOT be sent in response to any message except Sigma1 or PBKDFParamRequest
//   - R Flag SHALL be 0 (no response expected)
//   - S Flag SHALL be 0
func SendBusy(waitTimeMs uint16) []byte {
	return Busy(waitTimeMs).Encode()
}

// IsCloseSession returns true if the status report is a CloseSession.
func IsCloseSession(status *StatusReport) bool {
	return status.GeneralCode == GeneralCodeSuccess &&
		status.IsSecureChannel() &&
		status.SecureChannelCode() == ProtocolCodeCloseSession
}

// IsBusyStatus returns true if the status report is a Busy status.
func IsBusyStatus(status *StatusReport) bool {
	return status.IsBusy()
}

// NoSharedTrustRoots creates a NoSharedTrustRoots error status report.
// Sent during CASE when no common root of trust is found.
func NoSharedTrustRoots() *StatusReport {
	return NewSecureChannelStatusReport(GeneralCodeFailure, ProtocolCodeNoSharedRoot)
}

// RequiredCATMismatch creates a status report for CAT mismatch errors.
// Sent during CASE Sigma2 validation when required CATs don't match.
func RequiredCATMismatch() *StatusReport {
	return NewSecureChannelStatusReport(GeneralCodeFailure, ProtocolCode(0x0005))
}

// SessionNotFound creates a SessionNotFound error status report.
func SessionNotFound() *StatusReport {
	return NewSecureChannelStatusReport(GeneralCodeFailure, ProtocolCodeSessionNotFound)
}
