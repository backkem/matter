package session

import (
	"sync"
	"time"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/message"
)

// Key size constants.
const (
	// SessionKeySize is the size of I2R and R2I keys (16 bytes for AES-128).
	SessionKeySize = 16

	// ResumptionIDSize is the size of the resumption ID (16 bytes).
	ResumptionIDSize = 16

	// MaxCATCount is the maximum number of CASE Authenticated Tags.
	MaxCATCount = 3
)

// SecureContext holds state for an established secure session.
// Created by pkg/securechannel after successful PASE/CASE completion.
//
// This context stores all 15 fields specified in Spec Section 4.13.3.1:
//  1. Session Type (PASE/CASE)
//  2. Session Role (Initiator/Responder)
//  3. Local Session Identifier
//  4. Peer Session Identifier
//  5. I2RKey (Initiator-to-Responder encryption key)
//  6. R2IKey (Responder-to-Initiator encryption key)
//  7. SharedSecret (for CASE resumption)
//  8. Local Message Counter
//  9. Message Reception State
//  10. Local Fabric Index
//  11. Peer Node ID
//  12. Resumption ID
//  13. SessionTimestamp
//  14. ActiveTimestamp
//  15. Session Parameters (IdleInterval, ActiveInterval, ActiveThreshold)
//
// Additionally, up to 3 CASE Authenticated Tags (CATs) may be stored.
type SecureContext struct {
	// === Identity (fields 1-4) ===
	sessionType    SessionType // 1. PASE or CASE
	role           SessionRole // 2. Initiator or Responder
	localSessionID uint16      // 3. Maps incoming messages to this context
	peerSessionID  uint16      // 4. Used in outgoing message Session ID field

	// === Keys (fields 5-7) ===
	i2rKey       []byte // 5. Initiator-to-Responder encryption key (16 bytes)
	r2iKey       []byte // 6. Responder-to-Initiator encryption key (16 bytes)
	sharedSecret []byte // 7. For CASE resumption (nil for PASE)

	// === Derived codecs (from keys) ===
	encryptCodec *message.Codec // For encrypting outgoing messages
	decryptCodec *message.Codec // For decrypting incoming messages

	// === Counters (fields 8-9) ===
	localCounter   *message.SessionCounter   // 8. Outbound message counter
	receptionState *message.ReceptionState   // 9. Inbound anti-replay

	// === Fabric binding (fields 10-11) ===
	fabricIndex fabric.FabricIndex // 10. Local fabric index (0 for PASE pre-AddNOC)
	peerNodeID  fabric.NodeID      // 11. Peer's node ID (0 for PASE)

	// === Local Node ID (for nonce construction) ===
	localNodeID fabric.NodeID // Our node ID (0 for PASE)

	// === Resumption (field 12) ===
	resumptionID [ResumptionIDSize]byte // 12. For session resumption

	// === Timestamps (fields 13-14) ===
	sessionTimestamp time.Time // 13. Last send/receive
	activeTimestamp  time.Time // 14. Last receive (for PeerActiveMode)

	// === Parameters (field 15) ===
	params Params // 15. MRP timing parameters

	// === CAT fields (up to 3) ===
	caseAuthTags []uint32 // CASE Authenticated Tags from NOC

	mu sync.RWMutex
}

// SecureContextConfig is used to create a new secure context after handshake.
type SecureContextConfig struct {
	SessionType    SessionType
	Role           SessionRole
	LocalSessionID uint16
	PeerSessionID  uint16
	I2RKey         []byte // 16 bytes
	R2IKey         []byte // 16 bytes
	SharedSecret   []byte // For CASE resumption (optional, nil for PASE)
	FabricIndex    fabric.FabricIndex
	PeerNodeID     fabric.NodeID
	LocalNodeID    fabric.NodeID // Our node ID (0 for PASE)
	Params         Params
	CaseAuthTags   []uint32 // Up to 3
}

// NewSecureContext creates a new secure session context.
// This is called by pkg/securechannel after successful PASE/CASE completion.
func NewSecureContext(config SecureContextConfig) (*SecureContext, error) {
	// Validate inputs
	if !config.SessionType.IsValid() {
		return nil, ErrInvalidSessionType
	}
	if !config.Role.IsValid() {
		return nil, ErrInvalidRole
	}
	if config.LocalSessionID == 0 {
		return nil, ErrInvalidSessionID
	}
	if len(config.I2RKey) != SessionKeySize {
		return nil, ErrInvalidKey
	}
	if len(config.R2IKey) != SessionKeySize {
		return nil, ErrInvalidKey
	}

	// For PASE sessions, NodeIDs should be 0 (Unspecified)
	// For CASE sessions, they should be the actual operational NodeIDs
	localNodeIDForNonce := uint64(config.LocalNodeID)
	peerNodeIDForNonce := uint64(config.PeerNodeID)
	if config.SessionType == SessionTypePASE {
		localNodeIDForNonce = 0
		peerNodeIDForNonce = 0
	}

	// Create codecs based on role
	// Initiator encrypts with I2R, decrypts with R2I
	// Responder encrypts with R2I, decrypts with I2R
	var encryptCodec, decryptCodec *message.Codec
	var err error

	if config.Role == SessionRoleInitiator {
		encryptCodec, err = message.NewCodec(config.I2RKey, localNodeIDForNonce)
		if err != nil {
			return nil, err
		}
		decryptCodec, err = message.NewCodec(config.R2IKey, peerNodeIDForNonce)
		if err != nil {
			return nil, err
		}
	} else {
		encryptCodec, err = message.NewCodec(config.R2IKey, localNodeIDForNonce)
		if err != nil {
			return nil, err
		}
		decryptCodec, err = message.NewCodec(config.I2RKey, peerNodeIDForNonce)
		if err != nil {
			return nil, err
		}
	}

	now := time.Now()

	ctx := &SecureContext{
		sessionType:      config.SessionType,
		role:             config.Role,
		localSessionID:   config.LocalSessionID,
		peerSessionID:    config.PeerSessionID,
		i2rKey:           make([]byte, SessionKeySize),
		r2iKey:           make([]byte, SessionKeySize),
		encryptCodec:     encryptCodec,
		decryptCodec:     decryptCodec,
		localCounter:     message.NewSessionCounter(),
		receptionState:   message.NewReceptionStateEmpty(),
		fabricIndex:      config.FabricIndex,
		peerNodeID:       config.PeerNodeID,
		localNodeID:      config.LocalNodeID,
		sessionTimestamp: now,
		activeTimestamp:  now,
		params:           config.Params.WithDefaults(),
	}

	// Copy keys (don't hold references to caller's slices)
	copy(ctx.i2rKey, config.I2RKey)
	copy(ctx.r2iKey, config.R2IKey)

	// Copy shared secret if provided (CASE only)
	if len(config.SharedSecret) > 0 {
		ctx.sharedSecret = make([]byte, len(config.SharedSecret))
		copy(ctx.sharedSecret, config.SharedSecret)
	}

	// Copy CATs (up to 3)
	if len(config.CaseAuthTags) > 0 {
		count := len(config.CaseAuthTags)
		if count > MaxCATCount {
			count = MaxCATCount
		}
		ctx.caseAuthTags = make([]uint32, count)
		copy(ctx.caseAuthTags, config.CaseAuthTags[:count])
	}

	return ctx, nil
}

// LocalSessionID returns the local session identifier.
// This is used to route incoming messages to this context.
func (s *SecureContext) LocalSessionID() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localSessionID
}

// PeerSessionID returns the peer's session identifier.
// This must be placed in the Session ID field of outgoing messages.
func (s *SecureContext) PeerSessionID() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peerSessionID
}

// SessionType returns whether this is a PASE or CASE session.
func (s *SecureContext) SessionType() SessionType {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionType
}

// Role returns the session role (initiator or responder).
func (s *SecureContext) Role() SessionRole {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.role
}

// FabricIndex returns the fabric index for this session.
// Returns 0 for PASE sessions before AddNOC.
func (s *SecureContext) FabricIndex() fabric.FabricIndex {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fabricIndex
}

// SetFabricIndex sets the fabric index.
// Used after AddNOC completes on a PASE session.
func (s *SecureContext) SetFabricIndex(index fabric.FabricIndex) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fabricIndex = index
}

// PeerNodeID returns the peer's node ID.
// Returns 0 for PASE sessions.
func (s *SecureContext) PeerNodeID() fabric.NodeID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peerNodeID
}

// LocalNodeID returns the local node ID.
// Returns 0 for PASE sessions.
func (s *SecureContext) LocalNodeID() fabric.NodeID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localNodeID
}

// Encrypt encrypts a message for transmission.
// Returns the complete encrypted frame bytes.
//
// The header's SessionID will be set to the peer's session ID.
// The header's MessageCounter will be set from the local counter.
func (s *SecureContext) Encrypt(header *message.MessageHeader, protocol *message.ProtocolHeader, payload []byte, privacy bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get next message counter
	counter, err := s.localCounter.Next()
	if err != nil {
		return nil, ErrCounterExhausted
	}

	// Set header fields
	header.SessionID = s.peerSessionID
	header.MessageCounter = counter

	// Encrypt using the appropriate codec
	encrypted, err := s.encryptCodec.Encode(header, protocol, payload, privacy)
	if err != nil {
		return nil, err
	}

	// Update timestamp
	s.sessionTimestamp = time.Now()

	return encrypted, nil
}

// Decrypt decrypts an incoming message.
// Returns the decrypted frame with protocol header and payload.
//
// The message counter is verified against the reception state for replay detection.
func (s *SecureContext) Decrypt(data []byte) (*message.Frame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get the NodeID for nonce construction
	peerNodeIDForNonce := uint64(s.peerNodeID)
	if s.sessionType == SessionTypePASE {
		peerNodeIDForNonce = 0
	}

	// Decrypt using the appropriate codec
	frame, err := s.decryptCodec.Decode(data, peerNodeIDForNonce)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Verify message counter for replay
	if !s.receptionState.CheckAndAccept(frame.Header.MessageCounter, false) {
		return nil, ErrReplayDetected
	}

	// Update timestamps
	now := time.Now()
	s.sessionTimestamp = now
	s.activeTimestamp = now

	return frame, nil
}

// NextCounter returns and increments the local message counter.
// Returns ErrCounterExhausted if the counter has wrapped.
func (s *SecureContext) NextCounter() (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counter, err := s.localCounter.Next()
	if err != nil {
		return 0, ErrCounterExhausted
	}
	return counter, nil
}

// CheckCounter verifies an incoming message counter for replay.
// Returns true if the message should be accepted.
func (s *SecureContext) CheckCounter(counter uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receptionState.CheckAndAccept(counter, false)
}

// IsPeerActive returns whether the peer is in active mode.
// Used for MRP retransmission timing.
// Per Spec 4.13.3.1 field 15d: PeerActiveMode = (now - ActiveTimestamp) < ActiveThreshold
func (s *SecureContext) IsPeerActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.activeTimestamp) < s.params.ActiveThreshold
}

// MarkActivity updates timestamps on message send/receive.
// Call with isReceive=true for incoming messages, false for outgoing.
func (s *SecureContext) MarkActivity(isReceive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sessionTimestamp = now
	if isReceive {
		s.activeTimestamp = now
	}
}

// GetParams returns the MRP parameters.
func (s *SecureContext) GetParams() Params {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.params
}

// SetParams sets the MRP parameters.
func (s *SecureContext) SetParams(params Params) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.params = params.WithDefaults()
}

// SetResumptionID sets the resumption ID after CASE completion.
func (s *SecureContext) SetResumptionID(id [ResumptionIDSize]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resumptionID = id
}

// ResumptionID returns the resumption ID for session resumption.
func (s *SecureContext) ResumptionID() [ResumptionIDSize]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resumptionID
}

// SharedSecret returns the shared secret for CASE resumption.
// Returns nil for PASE sessions.
func (s *SecureContext) SharedSecret() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sharedSecret == nil {
		return nil
	}
	// Return a copy to prevent modification
	result := make([]byte, len(s.sharedSecret))
	copy(result, s.sharedSecret)
	return result
}

// CaseAuthTags returns the CASE Authenticated Tags.
// Returns nil for PASE sessions or if no tags are present.
func (s *SecureContext) CaseAuthTags() []uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.caseAuthTags == nil {
		return nil
	}
	// Return a copy to prevent modification
	result := make([]uint32, len(s.caseAuthTags))
	copy(result, s.caseAuthTags)
	return result
}

// SessionTimestamp returns the time of last message activity.
func (s *SecureContext) SessionTimestamp() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionTimestamp
}

// ActiveTimestamp returns the time of last received message.
func (s *SecureContext) ActiveTimestamp() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeTimestamp
}

// getEncryptKey returns the key used for encrypting outgoing messages.
func (s *SecureContext) getEncryptKey() []byte {
	if s.role == SessionRoleInitiator {
		return s.i2rKey
	}
	return s.r2iKey
}

// getDecryptKey returns the key used for decrypting incoming messages.
func (s *SecureContext) getDecryptKey() []byte {
	if s.role == SessionRoleInitiator {
		return s.r2iKey
	}
	return s.i2rKey
}

// ZeroizeKeys securely clears the session keys from memory.
// Call this when closing a session.
func (s *SecureContext) ZeroizeKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear keys
	for i := range s.i2rKey {
		s.i2rKey[i] = 0
	}
	for i := range s.r2iKey {
		s.r2iKey[i] = 0
	}
	if s.sharedSecret != nil {
		for i := range s.sharedSecret {
			s.sharedSecret[i] = 0
		}
	}

	// Invalidate codecs
	s.encryptCodec = nil
	s.decryptCodec = nil
}
