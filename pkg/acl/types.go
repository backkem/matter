package acl

import "github.com/backkem/matter/pkg/fabric"

// NodeID range constants for different node types.
// Spec: Section 2.5.5.1
const (
	// NodeIDMinOperational is the minimum valid operational node ID.
	NodeIDMinOperational uint64 = 0x0000_0000_0000_0001

	// NodeIDMaxOperational is the maximum valid operational node ID.
	NodeIDMaxOperational uint64 = 0xFFFF_FFEF_FFFF_FFFF

	// NodeIDUnspecified represents an unspecified/invalid node ID.
	NodeIDUnspecified uint64 = 0x0000_0000_0000_0000
)

// Group NodeID range constants.
// Spec: Section 2.5.5.2
const (
	// NodeIDMinGroup is the minimum group-type NodeID.
	NodeIDMinGroup uint64 = 0xFFFF_FFFF_FFFF_0001

	// NodeIDMaxGroup is the maximum group-type NodeID.
	NodeIDMaxGroup uint64 = 0xFFFF_FFFF_FFFF_FFFF

	// GroupIDMin is the minimum valid group ID.
	GroupIDMin uint16 = 0x0001

	// GroupIDMax is the maximum valid group ID.
	GroupIDMax uint16 = 0xFFFF
)

// PAKE Key ID (PASE) NodeID constants.
// Spec: Section 2.5.5.4
const (
	// NodeIDMinPAKE is the minimum PAKE-type NodeID.
	NodeIDMinPAKE uint64 = 0xFFFF_FFFB_0000_0000

	// NodeIDMaxPAKE is the maximum PAKE-type NodeID.
	NodeIDMaxPAKE uint64 = 0xFFFF_FFFB_0000_FFFF
)

// IsOperationalNodeID returns true if the NodeID is in the operational range.
func IsOperationalNodeID(nodeID uint64) bool {
	return nodeID >= NodeIDMinOperational && nodeID <= NodeIDMaxOperational
}

// IsGroupNodeID returns true if the NodeID represents a group.
func IsGroupNodeID(nodeID uint64) bool {
	return nodeID >= NodeIDMinGroup && nodeID <= NodeIDMaxGroup
}

// IsPAKENodeID returns true if the NodeID represents a PAKE key ID.
func IsPAKENodeID(nodeID uint64) bool {
	return nodeID >= NodeIDMinPAKE && nodeID <= NodeIDMaxPAKE
}

// NodeIDFromGroupID creates a group-type NodeID from a group ID.
func NodeIDFromGroupID(groupID uint16) uint64 {
	return 0xFFFF_FFFF_FFFF_0000 | uint64(groupID)
}

// GroupIDFromNodeID extracts the group ID from a group-type NodeID.
// Returns 0 if not a group NodeID.
func GroupIDFromNodeID(nodeID uint64) uint16 {
	if !IsGroupNodeID(nodeID) {
		return 0
	}
	return uint16(nodeID & 0xFFFF)
}

// NodeIDFromPAKEKeyID creates a PAKE-type NodeID from a PAKE key ID.
func NodeIDFromPAKEKeyID(keyID uint16) uint64 {
	return NodeIDMinPAKE | uint64(keyID)
}

// IsValidGroupID returns true if the group ID is in the valid range.
func IsValidGroupID(groupID uint16) bool {
	return groupID >= GroupIDMin && groupID <= GroupIDMax
}

// Target defines what resource(s) an ACL entry grants access to.
// Spec: Section 9.10.5.5 (AccessControlTargetStruct)
//
// A target specifies a combination of:
//   - Cluster (optional): Specific cluster ID, or nil for wildcard
//   - Endpoint (optional): Specific endpoint ID, or nil for wildcard
//   - DeviceType (optional): Device type ID, or nil for wildcard
//
// Constraints:
//   - At least one field must be set (no empty targets)
//   - Endpoint and DeviceType are mutually exclusive
type Target struct {
	Cluster    *uint32 // nil = wildcard (all clusters)
	Endpoint   *uint16 // nil = wildcard (all endpoints)
	DeviceType *uint32 // nil = wildcard (all device types)
}

// NewTargetCluster creates a target matching a specific cluster on any endpoint.
func NewTargetCluster(cluster uint32) Target {
	return Target{Cluster: &cluster}
}

// NewTargetEndpoint creates a target matching any cluster on a specific endpoint.
func NewTargetEndpoint(endpoint uint16) Target {
	return Target{Endpoint: &endpoint}
}

// NewTargetDeviceType creates a target matching any cluster on endpoints with the device type.
func NewTargetDeviceType(deviceType uint32) Target {
	return Target{DeviceType: &deviceType}
}

// NewTargetClusterEndpoint creates a target matching a specific cluster on a specific endpoint.
func NewTargetClusterEndpoint(cluster uint32, endpoint uint16) Target {
	return Target{Cluster: &cluster, Endpoint: &endpoint}
}

// NewTargetClusterDeviceType creates a target matching a specific cluster on device type endpoints.
func NewTargetClusterDeviceType(cluster uint32, deviceType uint32) Target {
	return Target{Cluster: &cluster, DeviceType: &deviceType}
}

// IsEmpty returns true if no fields are set.
func (t Target) IsEmpty() bool {
	return t.Cluster == nil && t.Endpoint == nil && t.DeviceType == nil
}

// HasCluster returns true if a specific cluster is targeted.
func (t Target) HasCluster() bool {
	return t.Cluster != nil
}

// HasEndpoint returns true if a specific endpoint is targeted.
func (t Target) HasEndpoint() bool {
	return t.Endpoint != nil
}

// HasDeviceType returns true if a device type is targeted.
func (t Target) HasDeviceType() bool {
	return t.DeviceType != nil
}

// Entry represents a single ACL entry.
// Spec: Section 9.10.5.6 (AccessControlEntryStruct)
//
// An entry grants a privilege level to subjects for targets:
//   - FabricIndex: The fabric this entry belongs to
//   - Privilege: The access level granted (View, Operate, Manage, Administer)
//   - AuthMode: Required authentication mode (CASE or Group; PASE not stored)
//   - Subjects: Who gets access (empty = wildcard for CASE/Group)
//   - Targets: What resources (empty = wildcard, all resources)
type Entry struct {
	FabricIndex fabric.FabricIndex // Owning fabric (1-254)
	Privilege   Privilege          // Access level granted
	AuthMode    AuthMode           // Required auth mode (CASE or Group)
	Subjects    []uint64           // NodeIDs, CAT NodeIDs, or Group NodeIDs
	Targets     []Target           // Resource targets (empty = all)
}

// SubjectDescriptor describes the identity making a request.
// Spec: Section 6.6.6.1.3 (Incoming Subject Descriptor - ISD)
//
// This is derived from the session context when a message arrives.
type SubjectDescriptor struct {
	// FabricIndex identifies the fabric (0 for PASE without fabric).
	FabricIndex fabric.FabricIndex

	// AuthMode is how the session was authenticated.
	AuthMode AuthMode

	// Subject is the primary subject identifier:
	//   - CASE: Operational NodeID
	//   - PASE: PAKE Key ID as NodeID
	//   - Group: Group ID as NodeID
	Subject uint64

	// CATs contains CASE Authenticated Tags from the certificate (CASE only).
	CATs CATValues

	// IsCommissioning is true if this is a PASE session during commissioning.
	// When true, implicit Administer privilege is granted.
	IsCommissioning bool
}

// RequestPath describes the target of an access control check.
type RequestPath struct {
	// Cluster is the cluster being accessed.
	Cluster uint32

	// Endpoint is the endpoint being accessed.
	Endpoint uint16

	// RequestType identifies the operation type.
	RequestType RequestType

	// EntityID is the specific attribute/command/event ID (nil for wildcards).
	EntityID *uint32
}

// NewRequestPath creates a request path for a specific cluster/endpoint.
func NewRequestPath(cluster uint32, endpoint uint16, reqType RequestType) RequestPath {
	return RequestPath{
		Cluster:     cluster,
		Endpoint:    endpoint,
		RequestType: reqType,
	}
}

// NewRequestPathWithEntity creates a request path with a specific entity ID.
func NewRequestPathWithEntity(cluster uint32, endpoint uint16, reqType RequestType, entityID uint32) RequestPath {
	return RequestPath{
		Cluster:     cluster,
		Endpoint:    endpoint,
		RequestType: reqType,
		EntityID:    &entityID,
	}
}
