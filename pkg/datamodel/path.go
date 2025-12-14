package datamodel

import "github.com/backkem/matter/pkg/im/message"

// Type aliases from im/message for convenience.
// These provide the fundamental ID types used throughout the data model.
type (
	// NodeID is a 64-bit node identifier.
	NodeID = message.NodeID

	// EndpointID is a 16-bit endpoint identifier.
	EndpointID = message.EndpointID

	// ClusterID is a 32-bit cluster identifier.
	ClusterID = message.ClusterID

	// AttributeID is a 32-bit attribute identifier.
	AttributeID = message.AttributeID

	// CommandID is a 32-bit command identifier.
	CommandID = message.CommandID

	// EventID is a 32-bit event identifier.
	EventID = message.EventID

	// ListIndex is a 16-bit list index for addressing list elements.
	ListIndex = message.ListIndex

	// DataVersion is a 32-bit version number for attribute data.
	DataVersion = message.DataVersion

	// EventNumber is a 64-bit monotonically increasing event counter.
	EventNumber = message.EventNumber

	// SubscriptionID is a 32-bit subscription identifier.
	SubscriptionID = message.SubscriptionID
)

// ConcreteClusterPath identifies a specific cluster instance on an endpoint.
// Used for routing IM requests to the correct cluster.
type ConcreteClusterPath struct {
	Endpoint EndpointID
	Cluster  ClusterID
}

// ConcreteAttributePath identifies a specific attribute within a cluster.
// Spec: Section 8.2.1.1
type ConcreteAttributePath struct {
	Endpoint  EndpointID
	Cluster   ClusterID
	Attribute AttributeID
}

// ClusterPath returns the cluster path portion.
func (p ConcreteAttributePath) ClusterPath() ConcreteClusterPath {
	return ConcreteClusterPath{
		Endpoint: p.Endpoint,
		Cluster:  p.Cluster,
	}
}

// ConcreteDataAttributePath extends ConcreteAttributePath with list operation info.
// Used when writing to list attributes.
type ConcreteDataAttributePath struct {
	ConcreteAttributePath
	ListIndex *ListIndex // nil = full list, value = specific index
}

// ConcreteCommandPath identifies a specific command within a cluster.
// Spec: Section 8.2.1.2
type ConcreteCommandPath struct {
	Endpoint EndpointID
	Cluster  ClusterID
	Command  CommandID
}

// ClusterPath returns the cluster path portion.
func (p ConcreteCommandPath) ClusterPath() ConcreteClusterPath {
	return ConcreteClusterPath{
		Endpoint: p.Endpoint,
		Cluster:  p.Cluster,
	}
}

// ConcreteEventPath identifies a specific event within a cluster.
// Spec: Section 8.2.1.3
type ConcreteEventPath struct {
	Endpoint EndpointID
	Cluster  ClusterID
	Event    EventID
}

// ClusterPath returns the cluster path portion.
func (p ConcreteEventPath) ClusterPath() ConcreteClusterPath {
	return ConcreteClusterPath{
		Endpoint: p.Endpoint,
		Cluster:  p.Cluster,
	}
}

// DeviceTypeID is a 32-bit device type identifier.
type DeviceTypeID uint32
