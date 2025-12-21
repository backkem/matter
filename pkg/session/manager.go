package session

import (
	"sync"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/message"
)

// DefaultMaxGroupPeers is the default maximum number of tracked group peers.
const DefaultMaxGroupPeers = 64

// Manager coordinates session contexts for message encryption/decryption.
// It provides the main API for session management used by pkg/securechannel
// and pkg/exchange.
//
// The Manager maintains:
//   - A table of secure session contexts (PASE/CASE)
//   - A table of unsecured session contexts (for PASE/CASE handshake)
//   - A table of group peer counters for anti-replay
//   - A global message counter for unsecured messages
type Manager struct {
	secure        *Table
	unsecured     map[fabric.NodeID]*UnsecuredContext // Keyed by ephemeral node ID
	groupPeers    *GroupPeerTable
	globalCounter *message.GlobalCounter

	mu sync.RWMutex
}

// ManagerConfig configures the session manager.
type ManagerConfig struct {
	// MaxSessions limits the number of concurrent secure sessions.
	// Default: DefaultMaxSessions (16)
	MaxSessions int

	// MaxGroupPeers limits the number of tracked group message senders.
	// Default: DefaultMaxGroupPeers (64)
	MaxGroupPeers int
}

// NewManager creates a new session manager.
func NewManager(config ManagerConfig) *Manager {
	if config.MaxSessions <= 0 {
		config.MaxSessions = DefaultMaxSessions
	}
	if config.MaxGroupPeers <= 0 {
		config.MaxGroupPeers = DefaultMaxGroupPeers
	}

	return &Manager{
		secure:        NewTable(config.MaxSessions),
		unsecured:     make(map[fabric.NodeID]*UnsecuredContext),
		groupPeers:    NewGroupPeerTable(config.MaxGroupPeers),
		globalCounter: message.NewGlobalCounter(),
	}
}

// AllocateSessionID allocates a new unique session ID.
// Returns ErrSessionTableFull if no more sessions can be added.
func (m *Manager) AllocateSessionID() (uint16, error) {
	return m.secure.AllocateID()
}

// AddSecureContext adds a new secure session context.
// Called by pkg/securechannel after successful PASE/CASE completion.
func (m *Manager) AddSecureContext(ctx *SecureContext) error {
	return m.secure.Add(ctx)
}

// RemoveSecureContext removes a secure session context by local session ID.
// The session's keys are zeroized before removal.
func (m *Manager) RemoveSecureContext(localSessionID uint16) {
	ctx := m.secure.FindByLocalID(localSessionID)
	if ctx != nil {
		ctx.ZeroizeKeys()
	}
	m.secure.Remove(localSessionID)
}

// FindSecureContext finds a secure context by local session ID.
// Returns nil if not found.
func (m *Manager) FindSecureContext(localSessionID uint16) *SecureContext {
	return m.secure.FindByLocalID(localSessionID)
}

// FindSecureContextByPeer finds all contexts for a specific peer.
// Returns an empty slice if none found.
func (m *Manager) FindSecureContextByPeer(fabricIndex fabric.FabricIndex, nodeID fabric.NodeID) []*SecureContext {
	return m.secure.FindByPeer(fabricIndex, nodeID)
}

// FindSecureContextByFabric finds all contexts on a specific fabric.
func (m *Manager) FindSecureContextByFabric(fabricIndex fabric.FabricIndex) []*SecureContext {
	return m.secure.FindByFabric(fabricIndex)
}

// SecureSessionCount returns the number of active secure sessions.
func (m *Manager) SecureSessionCount() int {
	return m.secure.Count()
}

// IsSecureTableFull returns true if no more secure sessions can be added.
func (m *Manager) IsSecureTableFull() bool {
	return m.secure.IsFull()
}

// FindOrCreateUnsecuredContext finds or creates an UnsecuredContext for incoming messages.
// Per Spec 4.13.2.1:
//   - Locate any context with matching Ephemeral Initiator Node ID (sourceNodeID)
//   - If not found and sourceNodeID is valid, create a new responder context
//   - Returns nil if sourceNodeID is invalid (0)
//
// This is used by pkg/exchange when receiving unencrypted messages (SessionID == 0).
func (m *Manager) FindOrCreateUnsecuredContext(sourceNodeID fabric.NodeID) (*UnsecuredContext, error) {
	if sourceNodeID == 0 {
		return nil, ErrInvalidNodeID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Look for existing context with this ephemeral initiator node ID
	if ctx, exists := m.unsecured[sourceNodeID]; exists {
		return ctx, nil
	}

	// Create new responder context per Spec 4.13.2.1
	// The context will have its own randomly-generated ephemeral node ID
	ctx, err := NewUnsecuredContext(SessionRoleResponder)
	if err != nil {
		return nil, err
	}

	// Store the peer's ephemeral node ID (the initiator's node ID)
	// This will be used as the destination in our responses
	ctx.SetPeerEphemeralNodeID(sourceNodeID)

	// Index by initiator's ephemeral node ID for message routing
	m.unsecured[sourceNodeID] = ctx
	return ctx, nil
}

// CreateUnsecuredInitiatorContext creates a new UnsecuredContext for the initiator.
// Per Spec 4.13.2.1: Called when sending the first message of an unencrypted exchange.
// The ephemeral node ID is randomly generated and guaranteed not to collide with
// any ongoing unsecured sessions.
func (m *Manager) CreateUnsecuredInitiatorContext() (*UnsecuredContext, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Try to create a context with non-colliding ephemeral ID
	// Per Spec: "SHALL select an ID that does not conflict with any ephemeral node IDs
	// for any other ongoing unsecured sessions opened by the initiator"
	const maxAttempts = 100
	for i := 0; i < maxAttempts; i++ {
		ctx, err := NewUnsecuredContext(SessionRoleInitiator)
		if err != nil {
			return nil, err
		}

		ephemeralID := ctx.EphemeralNodeID()
		if _, exists := m.unsecured[ephemeralID]; !exists {
			// No collision - use this context
			m.unsecured[ephemeralID] = ctx
			return ctx, nil
		}
	}

	return nil, ErrSessionTableFull
}

// FindUnsecuredContext finds an UnsecuredContext by ephemeral node ID.
// Returns nil if not found.
func (m *Manager) FindUnsecuredContext(ephemeralNodeID fabric.NodeID) *UnsecuredContext {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.unsecured[ephemeralNodeID]
}

// RemoveUnsecuredContext removes an UnsecuredContext.
// Called after successful session establishment or on error.
func (m *Manager) RemoveUnsecuredContext(ephemeralNodeID fabric.NodeID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.unsecured, ephemeralNodeID)
}

// UnsecuredSessionCount returns the number of active unsecured sessions.
func (m *Manager) UnsecuredSessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.unsecured)
}

// GlobalCounter returns the global message counter for unsecured messages.
// Used during PASE/CASE handshake.
func (m *Manager) GlobalCounter() *message.GlobalCounter {
	return m.globalCounter
}

// NextGlobalCounter returns and increments the global message counter.
func (m *Manager) NextGlobalCounter() (uint32, error) {
	return m.globalCounter.Next()
}

// CheckGroupCounter verifies a group message counter using trust-first policy.
// Returns true if the message should be accepted.
func (m *Manager) CheckGroupCounter(fabricIndex fabric.FabricIndex, sourceNodeID fabric.NodeID, counter uint32) bool {
	return m.groupPeers.CheckCounter(fabricIndex, sourceNodeID, counter)
}

// RemoveGroupPeer removes group counter tracking for a specific peer.
func (m *Manager) RemoveGroupPeer(fabricIndex fabric.FabricIndex, nodeID fabric.NodeID) {
	m.groupPeers.RemovePeer(fabricIndex, nodeID)
}

// RemoveFabric removes all sessions and group peers on a fabric.
// Called when a fabric is removed from the node.
func (m *Manager) RemoveFabric(fabricIndex fabric.FabricIndex) {
	// Remove all secure sessions on this fabric
	sessions := m.secure.FindByFabric(fabricIndex)
	for _, ctx := range sessions {
		ctx.ZeroizeKeys()
	}
	m.secure.RemoveByFabric(fabricIndex)

	// Remove all group peer tracking for this fabric
	m.groupPeers.RemoveFabric(fabricIndex)
}

// RemovePeer removes all sessions to a specific peer.
// Called when a peer node is removed.
func (m *Manager) RemovePeer(fabricIndex fabric.FabricIndex, nodeID fabric.NodeID) {
	// Remove secure sessions
	sessions := m.secure.FindByPeer(fabricIndex, nodeID)
	for _, ctx := range sessions {
		ctx.ZeroizeKeys()
	}
	m.secure.RemoveByPeer(fabricIndex, nodeID)

	// Remove group peer tracking
	m.groupPeers.RemovePeer(fabricIndex, nodeID)
}

// Clear removes all sessions and resets the manager.
// This zeroizes all session keys.
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Zeroize all session keys
	m.secure.ForEach(func(ctx *SecureContext) bool {
		ctx.ZeroizeKeys()
		return true
	})

	// Clear tables
	m.secure.Clear()
	m.unsecured = make(map[fabric.NodeID]*UnsecuredContext)
	m.groupPeers.Clear()

	// Reset global counter
	m.globalCounter = message.NewGlobalCounter()
}

// ForEachSecureSession calls fn for each secure session.
// The callback receives the session context and should return true to continue.
func (m *Manager) ForEachSecureSession(fn func(*SecureContext) bool) {
	m.secure.ForEach(fn)
}

// GroupPeerCount returns the number of tracked group peers.
func (m *Manager) GroupPeerCount() int {
	return m.groupPeers.Count()
}
