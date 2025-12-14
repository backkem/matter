package session

import (
	"sync"

	"github.com/backkem/matter/pkg/fabric"
)

// Session ID constants.
const (
	// MinSessionID is the minimum valid secure session ID.
	// Session ID 0 is reserved for unsecured sessions.
	MinSessionID uint16 = 1

	// MaxSessionID is the maximum valid session ID.
	MaxSessionID uint16 = 0xFFFF

	// DefaultMaxSessions is the default maximum number of concurrent sessions.
	DefaultMaxSessions = 16
)

// Table manages secure session contexts.
// It handles session ID allocation, lookup, and lifecycle management.
//
// Session IDs are allocated sequentially, wrapping around when reaching
// MaxSessionID. The table ensures IDs are unique among active sessions.
type Table struct {
	sessions    map[uint16]*SecureContext
	maxSessions int
	nextID      uint16 // Next ID to try allocating

	mu sync.RWMutex
}

// NewTable creates a new session table.
// maxSessions limits the number of concurrent sessions (0 uses DefaultMaxSessions).
func NewTable(maxSessions int) *Table {
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}

	return &Table{
		sessions:    make(map[uint16]*SecureContext),
		maxSessions: maxSessions,
		nextID:      MinSessionID,
	}
}

// AllocateID generates a unique session ID in the range [1, 65535].
// Returns ErrSessionTableFull if the table is at capacity.
// Returns ErrSessionIDExhausted if all 65535 IDs are in use (extremely unlikely).
func (t *Table) AllocateID() (uint16, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check capacity
	if len(t.sessions) >= t.maxSessions {
		return 0, ErrSessionTableFull
	}

	// Find an unused ID starting from nextID
	startID := t.nextID
	for {
		id := t.nextID

		// Advance nextID for next allocation (wrap around, skip 0)
		t.nextID++
		if t.nextID == 0 {
			t.nextID = MinSessionID
		}

		// Check if this ID is available
		if _, exists := t.sessions[id]; !exists {
			return id, nil
		}

		// If we've wrapped all the way around, no IDs available
		if t.nextID == startID {
			return 0, ErrSessionIDExhausted
		}
	}
}

// Add adds a session context to the table.
// The session's LocalSessionID must be unique and non-zero.
func (t *Table) Add(ctx *SecureContext) error {
	if ctx == nil {
		return ErrInvalidSessionID
	}

	id := ctx.LocalSessionID()
	if id == 0 {
		return ErrInvalidSessionID
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check capacity
	if len(t.sessions) >= t.maxSessions {
		return ErrSessionTableFull
	}

	// Check for duplicate
	if _, exists := t.sessions[id]; exists {
		return ErrDuplicateSession
	}

	t.sessions[id] = ctx
	return nil
}

// Remove removes a session context from the table.
// No error is returned if the session doesn't exist.
func (t *Table) Remove(localSessionID uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, localSessionID)
}

// FindByLocalID looks up a session by its local session ID.
// Returns nil if not found.
func (t *Table) FindByLocalID(id uint16) *SecureContext {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessions[id]
}

// FindByPeer finds all sessions to a specific peer on a specific fabric.
// Returns an empty slice if none found.
func (t *Table) FindByPeer(fabricIndex fabric.FabricIndex, nodeID fabric.NodeID) []*SecureContext {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var result []*SecureContext
	for _, ctx := range t.sessions {
		if ctx.FabricIndex() == fabricIndex && ctx.PeerNodeID() == nodeID {
			result = append(result, ctx)
		}
	}
	return result
}

// FindByFabric finds all sessions on a specific fabric.
// Returns an empty slice if none found.
func (t *Table) FindByFabric(fabricIndex fabric.FabricIndex) []*SecureContext {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var result []*SecureContext
	for _, ctx := range t.sessions {
		if ctx.FabricIndex() == fabricIndex {
			result = append(result, ctx)
		}
	}
	return result
}

// Count returns the number of active sessions.
func (t *Table) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// IsFull returns true if no more sessions can be added.
func (t *Table) IsFull() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions) >= t.maxSessions
}

// MaxSessions returns the maximum number of sessions allowed.
func (t *Table) MaxSessions() int {
	return t.maxSessions
}

// Clear removes all sessions from the table.
// Sessions are not zeroized; call ZeroizeKeys on each session if needed.
func (t *Table) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions = make(map[uint16]*SecureContext)
}

// ForEach calls fn for each session in the table.
// The callback should not modify the table.
func (t *Table) ForEach(fn func(*SecureContext) bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, ctx := range t.sessions {
		if !fn(ctx) {
			return
		}
	}
}

// RemoveByFabric removes all sessions on a specific fabric.
// Returns the number of sessions removed.
func (t *Table) RemoveByFabric(fabricIndex fabric.FabricIndex) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	count := 0
	for id, ctx := range t.sessions {
		if ctx.FabricIndex() == fabricIndex {
			delete(t.sessions, id)
			count++
		}
	}
	return count
}

// RemoveByPeer removes all sessions to a specific peer.
// Returns the number of sessions removed.
func (t *Table) RemoveByPeer(fabricIndex fabric.FabricIndex, nodeID fabric.NodeID) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	count := 0
	for id, ctx := range t.sessions {
		if ctx.FabricIndex() == fabricIndex && ctx.PeerNodeID() == nodeID {
			delete(t.sessions, id)
			count++
		}
	}
	return count
}
