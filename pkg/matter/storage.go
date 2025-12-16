package matter

import (
	"github.com/backkem/matter/pkg/acl"
	"github.com/backkem/matter/pkg/fabric"
)

// Storage abstracts persistent storage for Matter state.
// Implementations can use files, databases, or in-memory storage.
//
// All methods must be safe for concurrent use.
type Storage interface {
	// Fabric credentials
	LoadFabrics() ([]*fabric.FabricInfo, error)
	SaveFabric(info *fabric.FabricInfo) error
	DeleteFabric(index fabric.FabricIndex) error

	// ACL entries
	LoadACLs() ([]*acl.Entry, error)
	SaveACLs(entries []*acl.Entry) error

	// Message counters (for replay protection)
	LoadCounters() (*CounterState, error)
	SaveCounters(state *CounterState) error

	// Group keys
	LoadGroupKeys() ([]GroupKeyEntry, error)
	SaveGroupKeys(keys []GroupKeyEntry) error
}

// CounterState holds message counter state for persistence.
type CounterState struct {
	// LocalCounter is the next message counter to use for outgoing messages.
	// Per Spec 4.6.1.1, this should be randomly initialized and persisted.
	LocalCounter uint32

	// PeerCounters maps (FabricIndex, NodeID) to last seen peer counter.
	// Used for replay protection per Spec 4.6.5.
	PeerCounters map[PeerKey]uint32

	// GroupCounters maps GroupID to last seen group counter.
	GroupCounters map[uint16]uint32
}

// PeerKey identifies a peer for counter tracking.
type PeerKey struct {
	FabricIndex fabric.FabricIndex
	NodeID      fabric.NodeID
}

// GroupKeyEntry represents a group key for multicast messaging.
type GroupKeyEntry struct {
	// FabricIndex identifies the fabric this key belongs to.
	FabricIndex fabric.FabricIndex

	// GroupKeySetID is the key set identifier (0-65535).
	GroupKeySetID uint16

	// EpochKey0, EpochKey1, EpochKey2 are the rotating epoch keys.
	// Each is 16 bytes (AES-128 key).
	EpochKey0 []byte
	EpochKey1 []byte
	EpochKey2 []byte

	// EpochStartTime0, EpochStartTime1, EpochStartTime2 are epoch start times.
	// Microseconds since Unix epoch.
	EpochStartTime0 uint64
	EpochStartTime1 uint64
	EpochStartTime2 uint64

	// GroupKeySecurityPolicy specifies the security policy.
	// 0 = TrustFirst, 1 = CacheAndSync
	GroupKeySecurityPolicy uint8

	// GroupKeyMulticastPolicy specifies multicast handling.
	// 0 = PerGroupID, 1 = AllNodes
	GroupKeyMulticastPolicy uint8
}

// NewCounterState creates a new CounterState with initialized maps.
func NewCounterState() *CounterState {
	return &CounterState{
		LocalCounter:  0,
		PeerCounters:  make(map[PeerKey]uint32),
		GroupCounters: make(map[uint16]uint32),
	}
}

// Clone creates a deep copy of the counter state.
func (c *CounterState) Clone() *CounterState {
	if c == nil {
		return NewCounterState()
	}

	clone := &CounterState{
		LocalCounter:  c.LocalCounter,
		PeerCounters:  make(map[PeerKey]uint32, len(c.PeerCounters)),
		GroupCounters: make(map[uint16]uint32, len(c.GroupCounters)),
	}

	for k, v := range c.PeerCounters {
		clone.PeerCounters[k] = v
	}
	for k, v := range c.GroupCounters {
		clone.GroupCounters[k] = v
	}

	return clone
}
