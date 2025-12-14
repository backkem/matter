package session

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/message"
)

// UnsecuredContext holds state for an unsecured session during PASE/CASE handshake.
// Unsecured sessions are used for session establishment messages before encryption
// keys are negotiated.
//
// This context tracks:
//   - Session role (initiator/responder)
//   - Ephemeral Node ID (for message routing during handshake)
//   - Message reception state (for replay detection of unencrypted messages)
//   - MRP parameters
//
// See Spec Section 4.13.2.1 (Unsecured Session Context).
type UnsecuredContext struct {
	role            SessionRole
	ephemeralNodeID fabric.NodeID
	receptionState  *message.ReceptionState
	params          Params

	mu sync.RWMutex
}

// NewUnsecuredContext creates a new unsecured session context.
// The ephemeral node ID is randomly generated for initiators.
func NewUnsecuredContext(role SessionRole) (*UnsecuredContext, error) {
	if !role.IsValid() {
		return nil, ErrInvalidRole
	}

	ctx := &UnsecuredContext{
		role:           role,
		receptionState: message.NewReceptionStateEmpty(),
		params:         DefaultParams(),
	}

	// Initiators generate a random ephemeral node ID
	// Responders will have their ephemeral ID set from the incoming message
	if role == SessionRoleInitiator {
		nodeID, err := generateEphemeralNodeID()
		if err != nil {
			return nil, err
		}
		ctx.ephemeralNodeID = nodeID
	}

	return ctx, nil
}

// Role returns the session role (initiator or responder).
func (u *UnsecuredContext) Role() SessionRole {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.role
}

// EphemeralNodeID returns the ephemeral node ID for this session.
// For initiators, this is randomly generated at context creation.
// For responders, this is set from the incoming message's source node ID.
func (u *UnsecuredContext) EphemeralNodeID() fabric.NodeID {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.ephemeralNodeID
}

// SetEphemeralNodeID sets the ephemeral node ID.
// This is used by responders to record the initiator's ephemeral ID.
func (u *UnsecuredContext) SetEphemeralNodeID(nodeID fabric.NodeID) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ephemeralNodeID = nodeID
}

// CheckCounter verifies an incoming unencrypted message counter.
// Returns true if the message should be accepted (not a replay).
//
// Per Spec 4.6.5.3, unencrypted messages use relaxed duplicate detection:
// messages behind the window are accepted (may be from a rebooted peer).
func (u *UnsecuredContext) CheckCounter(counter uint32) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.receptionState.CheckUnencrypted(counter)
}

// GetParams returns the MRP parameters for this session.
func (u *UnsecuredContext) GetParams() Params {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.params
}

// SetParams sets the MRP parameters for this session.
// Parameters are typically learned from DNS-SD TXT records.
func (u *UnsecuredContext) SetParams(params Params) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.params = params.WithDefaults()
}

// generateEphemeralNodeID generates a random operational node ID.
// Per Spec 4.13.2.1, the ephemeral ID must be in the operational range
// and must not collide with other ongoing unsecured sessions.
func generateEphemeralNodeID() (fabric.NodeID, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}

	// Generate in operational node ID range [0x0000_0000_0000_0001, 0xFFFF_FFFE_FFFF_FFFD]
	nodeID := binary.LittleEndian.Uint64(buf[:])

	// Ensure it's in valid operational range
	// Map to range by masking and adjusting
	nodeID = (nodeID % (uint64(fabric.NodeIDMaxOperational) - uint64(fabric.NodeIDMinOperational))) + uint64(fabric.NodeIDMinOperational)

	return fabric.NodeID(nodeID), nil
}
