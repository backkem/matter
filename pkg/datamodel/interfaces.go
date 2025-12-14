package datamodel

import (
	"context"

	"github.com/backkem/matter/pkg/tlv"
)

// Node represents a Matter Node (Spec 7.8).
// A node is the highest addressable entity in the data model and contains
// one or more endpoints.
//
// C++ Reference: ProviderMetadataTree::Endpoints
type Node interface {
	// GetEndpoint returns the endpoint with the specified ID, or nil if not found.
	// Used when processing concrete paths.
	GetEndpoint(id EndpointID) Endpoint

	// GetEndpoints returns all registered endpoints in registration order.
	// Used for wildcard path expansion (Spec 8.2.1.6).
	GetEndpoints() []Endpoint
}

// Endpoint represents a component within a Node (Spec 7.9).
// An endpoint is an instance of a device type and contains clusters.
//
// C++ Reference: ProviderMetadataTree::ServerClusters
type Endpoint interface {
	// ID returns the endpoint number.
	ID() EndpointID

	// Entry returns the endpoint metadata.
	Entry() EndpointEntry

	// GetCluster returns the server cluster with the specified ID, or nil if not found.
	GetCluster(id ClusterID) Cluster

	// GetClusters returns all server clusters on this endpoint in registration order.
	// Used for wildcard path expansion.
	GetClusters() []Cluster

	// GetDeviceTypes returns the device types supported by this endpoint.
	GetDeviceTypes() []DeviceTypeEntry
}

// Cluster represents a server-side cluster instance (Spec 7.10).
// A cluster is the functional building block of the data model containing
// attributes, commands, and events.
//
// C++ Reference: DataModel::Provider
type Cluster interface {
	// ID returns the cluster ID (e.g., 0x0006 for OnOff).
	ID() ClusterID

	// EndpointID returns the endpoint this cluster belongs to.
	EndpointID() EndpointID

	// DataVersion returns the current cluster data version (Spec 7.10.3).
	// Must increment whenever any attribute changes.
	DataVersion() DataVersion

	// --- Global Attributes (Spec 7.13) ---

	// ClusterRevision returns the implemented cluster revision (0xFFFD).
	// Spec: Section 7.13.1
	ClusterRevision() uint16

	// FeatureMap returns the supported features bitmap (0xFFFC).
	// Spec: Section 7.13.2
	FeatureMap() uint32

	// --- Metadata for discovery ---

	// AttributeList returns metadata for all supported attributes.
	// Must include global attributes (ClusterRevision, FeatureMap, etc).
	// Spec: Section 7.13.3
	AttributeList() []AttributeEntry

	// AcceptedCommandList returns metadata for accepted (client→server) commands.
	// Spec: Section 7.13.4
	AcceptedCommandList() []CommandEntry

	// GeneratedCommandList returns IDs of generated (server→client) commands.
	// Spec: Section 7.13.5
	GeneratedCommandList() []CommandID

	// --- Operations ---

	// ReadAttribute reads a specific attribute into the TLV writer.
	// The cluster handles global attributes (ClusterRevision, FeatureMap, etc).
	// Returns error if the attribute doesn't exist.
	//
	// C++ Reference: DataModel::Provider::ReadAttribute
	ReadAttribute(ctx context.Context, req ReadAttributeRequest, w *tlv.Writer) error

	// WriteAttribute writes a specific attribute from the TLV reader.
	// Returns error if the attribute doesn't exist or write is not allowed.
	//
	// C++ Reference: DataModel::Provider::WriteAttribute
	WriteAttribute(ctx context.Context, req WriteAttributeRequest, r *tlv.Reader) error

	// InvokeCommand executes a command.
	// The reader contains the command fields; response data should be TLV-encoded.
	// Returns (response bytes, error). Response may be nil for status-only responses.
	//
	// C++ Reference: DataModel::Provider::InvokeCommand
	InvokeCommand(ctx context.Context, req InvokeRequest, r *tlv.Reader) ([]byte, error)
}

// ClusterWithEvents is an optional interface for clusters that support events.
type ClusterWithEvents interface {
	Cluster

	// EventList returns metadata for all supported events.
	EventList() []EventEntry
}

// ClusterWithListNotification is an optional interface for clusters that need
// to be notified about list write operations.
// C++ Reference: DataModel::Provider::ListAttributeWriteNotification
type ClusterWithListNotification interface {
	Cluster

	// ListAttributeWriteNotification is called at the start/end of list write operations.
	ListAttributeWriteNotification(path ConcreteAttributePath, op ListWriteOperation, fabricIndex uint8)
}

// AttributeChangeListener is notified when attribute values change.
// Used for subscription reporting.
type AttributeChangeListener interface {
	// OnAttributeChanged is called when an attribute value changes.
	OnAttributeChanged(path ConcreteAttributePath)
}

// DataModelProvider combines the Node interface with change notification.
// This is the main interface used by the Interaction Model engine.
type DataModelProvider interface {
	Node

	// SetAttributeChangeListener sets the listener for attribute changes.
	// Only one listener can be set at a time.
	SetAttributeChangeListener(listener AttributeChangeListener)
}
