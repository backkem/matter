package session

import (
	"sync"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/message"
)

// GroupContext holds ephemeral state for a received group message.
// Unlike SecureContext, GroupContext is created per-message when processing
// incoming group messages and destroyed after processing.
//
// Group sessions use symmetric keys from the Group Key Management cluster.
// The same key is used by all group members for encryption and decryption.
//
// See Spec Section 4.16.1 (Groupcast Session Context).
type GroupContext struct {
	sourceNodeID   fabric.NodeID
	fabricIndex    fabric.FabricIndex
	groupID        uint16
	groupSessionID uint16

	// Codec for decryption (uses group operational key)
	codec *message.Codec
}

// GroupContextConfig is used to create a group context for message processing.
type GroupContextConfig struct {
	SourceNodeID   fabric.NodeID
	FabricIndex    fabric.FabricIndex
	GroupID        uint16
	GroupSessionID uint16
	OperationalKey []byte // 16 bytes, from Group Key Management
}

// NewGroupContext creates a new group session context for processing a message.
// The operational key comes from the Group Key Management cluster.
func NewGroupContext(config GroupContextConfig) (*GroupContext, error) {
	if len(config.OperationalKey) != SessionKeySize {
		return nil, ErrInvalidKey
	}

	// For group messages, the source NodeID is used in nonce construction
	codec, err := message.NewCodec(config.OperationalKey, uint64(config.SourceNodeID))
	if err != nil {
		return nil, err
	}

	return &GroupContext{
		sourceNodeID:   config.SourceNodeID,
		fabricIndex:    config.FabricIndex,
		groupID:        config.GroupID,
		groupSessionID: config.GroupSessionID,
		codec:          codec,
	}, nil
}

// SourceNodeID returns the source node ID of the group message.
func (g *GroupContext) SourceNodeID() fabric.NodeID {
	return g.sourceNodeID
}

// FabricIndex returns the fabric index for this group session.
func (g *GroupContext) FabricIndex() fabric.FabricIndex {
	return g.fabricIndex
}

// GroupID returns the group ID.
func (g *GroupContext) GroupID() uint16 {
	return g.groupID
}

// GroupSessionID returns the group session ID.
// This is derived from the operational group key.
func (g *GroupContext) GroupSessionID() uint16 {
	return g.groupSessionID
}

// Decrypt decrypts an incoming group message.
// Returns the decrypted frame with protocol header and payload.
func (g *GroupContext) Decrypt(data []byte) (*message.Frame, error) {
	frame, err := g.codec.Decode(data, uint64(g.sourceNodeID))
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return frame, nil
}

// groupPeerKey uniquely identifies a group message sender.
type groupPeerKey struct {
	fabricIndex fabric.FabricIndex
	nodeID      fabric.NodeID
}

// GroupPeerTable tracks per-peer message counters for group messages.
// This implements the trust-first policy per Spec 4.6.5.2.2:
// the first message from a new peer is accepted unconditionally to
// establish the counter baseline.
//
// Group peers are tracked per-fabric because the same NodeID may appear
// on different fabrics.
type GroupPeerTable struct {
	peers    map[groupPeerKey]*message.ReceptionState
	maxPeers int

	mu sync.RWMutex
}

// NewGroupPeerTable creates a new group peer tracking table.
// maxPeers limits the number of tracked peers (0 means unlimited).
func NewGroupPeerTable(maxPeers int) *GroupPeerTable {
	return &GroupPeerTable{
		peers:    make(map[groupPeerKey]*message.ReceptionState),
		maxPeers: maxPeers,
	}
}

// CheckCounter verifies a group message counter using trust-first policy.
// Returns true if the message should be accepted.
//
// Trust-first policy (Spec 4.6.5.2.2):
//   - First message from a peer: trust unconditionally, establish baseline
//   - Subsequent messages: verify with rollover-aware counter checking
func (t *GroupPeerTable) CheckCounter(fabricIndex fabric.FabricIndex, sourceNodeID fabric.NodeID, counter uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := groupPeerKey{fabricIndex: fabricIndex, nodeID: sourceNodeID}

	state, exists := t.peers[key]
	if !exists {
		// First message from this peer - trust-first policy
		// Check capacity before adding
		if t.maxPeers > 0 && len(t.peers) >= t.maxPeers {
			return false // Capacity exceeded
		}

		// Create new state and accept the message
		state = message.NewReceptionState(counter)
		t.peers[key] = state
		return true
	}

	// Subsequent messages: verify with rollover awareness
	// Group messages allow rollover per spec
	return state.CheckAndAccept(counter, true)
}

// RemovePeer removes tracking for a specific peer.
// Call this when a node leaves the group or fabric.
func (t *GroupPeerTable) RemovePeer(fabricIndex fabric.FabricIndex, nodeID fabric.NodeID) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := groupPeerKey{fabricIndex: fabricIndex, nodeID: nodeID}
	delete(t.peers, key)
}

// RemoveFabric removes all peer tracking for a fabric.
// Call this when a fabric is removed.
func (t *GroupPeerTable) RemoveFabric(fabricIndex fabric.FabricIndex) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for key := range t.peers {
		if key.fabricIndex == fabricIndex {
			delete(t.peers, key)
		}
	}
}

// Count returns the number of tracked peers.
func (t *GroupPeerTable) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.peers)
}

// Clear removes all peer tracking.
func (t *GroupPeerTable) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers = make(map[groupPeerKey]*message.ReceptionState)
}
