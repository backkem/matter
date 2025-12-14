package datamodel

import "context"

// AtomicRequestType defines the type of atomic write request.
// Spec: Section 7.15.4
type AtomicRequestType int

const (
	// AtomicBeginWrite begins an atomic write operation.
	AtomicBeginWrite AtomicRequestType = iota

	// AtomicCommitWrite commits pending atomic writes.
	AtomicCommitWrite

	// AtomicRollbackWrite discards pending atomic writes.
	AtomicRollbackWrite
)

// String returns a human-readable name for the request type.
func (t AtomicRequestType) String() string {
	switch t {
	case AtomicBeginWrite:
		return "BeginWrite"
	case AtomicCommitWrite:
		return "CommitWrite"
	case AtomicRollbackWrite:
		return "RollbackWrite"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the request type is a defined value.
func (t AtomicRequestType) IsValid() bool {
	return t >= AtomicBeginWrite && t <= AtomicRollbackWrite
}

// AtomicAttributeStatus indicates the status of an attribute in an atomic write.
// Spec: Section 7.15.5
type AtomicAttributeStatus struct {
	// AttributeID is the attribute this status applies to.
	AttributeID AttributeID

	// StatusCode indicates the atomic status of the attribute.
	StatusCode uint8
}

// TransactionalCluster is an optional interface for clusters that support
// atomic writes (Spec Section 7.15).
//
// C++ Reference: ThermostatServer::AtomicWriteSession
type TransactionalCluster interface {
	Cluster

	// BeginAtomicWrite starts a transaction for the given attributes.
	// Returns the timeout the server will use (may differ from requested).
	// Spec: Section 7.15.6.4 (Begin Write)
	BeginAtomicWrite(ctx context.Context, attributeIDs []AttributeID, timeoutMs uint16) (uint16, []AtomicAttributeStatus, error)

	// CommitAtomicWrite applies all pending atomic writes.
	// Spec: Section 7.15.6.4 (Commit Write)
	CommitAtomicWrite(ctx context.Context, attributeIDs []AttributeID) ([]AtomicAttributeStatus, error)

	// RollbackAtomicWrite discards all pending atomic writes.
	// Spec: Section 7.15.6.4 (Rollback Write)
	RollbackAtomicWrite(ctx context.Context, attributeIDs []AttributeID) error
}

// AtomicWriteState tracks the state of an atomic write session.
// Spec: Section 7.15.3
type AtomicWriteState struct {
	// EndpointID is the endpoint of the cluster.
	EndpointID EndpointID

	// ClusterID is the ID of the cluster.
	ClusterID ClusterID

	// WriterNodeID is the operational node ID of the writer.
	WriterNodeID uint64

	// FabricIndex is the fabric of the accessing client.
	FabricIndex uint8

	// AttributeIDs are the attributes included in the atomic write.
	AttributeIDs []AttributeID

	// TimeoutMs is the timeout for the atomic write.
	TimeoutMs uint16
}

// ContainsAttribute returns true if the atomic write includes the given attribute.
func (s *AtomicWriteState) ContainsAttribute(attrID AttributeID) bool {
	for _, id := range s.AttributeIDs {
		if id == attrID {
			return true
		}
	}
	return false
}

// MatchesClient returns true if the given client matches this atomic write state.
func (s *AtomicWriteState) MatchesClient(nodeID uint64, fabricIndex uint8) bool {
	return s.WriterNodeID == nodeID && s.FabricIndex == fabricIndex
}

// AtomicRequest command field IDs (Spec 7.15.6)
const (
	AtomicRequestFieldRequestType      = 0
	AtomicRequestFieldAttributeRequests = 1
	AtomicRequestFieldTimeout           = 2
)

// AtomicResponse command field IDs (Spec 7.15.7)
const (
	AtomicResponseFieldStatusCode      = 0
	AtomicResponseFieldAttributeStatus = 1
	AtomicResponseFieldTimeout         = 2
)

// AtomicAttributeStatusStruct field IDs (Spec 7.15.5)
const (
	AtomicAttrStatusFieldAttributeID = 0
	AtomicAttrStatusFieldStatusCode  = 1
)
