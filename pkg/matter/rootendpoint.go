package matter

import (
	"github.com/backkem/matter/pkg/clusters/basic"
	"github.com/backkem/matter/pkg/clusters/descriptor"
	"github.com/backkem/matter/pkg/clusters/generalcommissioning"
	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/fabric"
)

// RootEndpointID is the ID of the root endpoint.
const RootEndpointID datamodel.EndpointID = 0

// RootDeviceType is the device type for the root node.
// Per Matter spec, device type 0x0016 is "Root Node".
const RootDeviceType uint32 = 0x0016

// RootDeviceTypeRevision is the revision for the root device type.
const RootDeviceTypeRevision uint8 = 1

// createRootEndpoint creates the root endpoint (endpoint 0) with required clusters.
// The root endpoint contains node-wide clusters like Basic Information,
// General Commissioning, and the Descriptor cluster.
func createRootEndpoint(config *NodeConfig, fabricTable *fabric.Table, node datamodel.Node) *Endpoint {
	ep := NewEndpoint(RootEndpointID).
		WithDeviceType(RootDeviceType, RootDeviceTypeRevision)

	// Descriptor Cluster (0x001D) - Required
	// Lists all endpoints and their device types
	descriptorCluster := descriptor.New(descriptor.Config{
		EndpointID: RootEndpointID,
		Node:       node,
	})
	ep.AddCluster(descriptorCluster)

	// Basic Information Cluster (0x0028) - Required
	// Provides device identity and version information
	basicInfoCluster := basic.New(basic.Config{
		EndpointID: RootEndpointID,
		DeviceInfo: basic.DeviceInfo{
			DataModelRevision:     17, // Matter 1.5 data model revision
			VendorName:            getVendorName(config.VendorID),
			VendorID:              uint16(config.VendorID),
			ProductName:           config.DeviceName,
			ProductID:             config.ProductID,
			HardwareVersion:       config.HardwareVersion,
			HardwareVersionString: "1.0",
			SoftwareVersion:       config.SoftwareVersion,
			SoftwareVersionString: config.SoftwareVersionString,
			UniqueID:              config.SerialNumber,
			CapabilityMinima: basic.CapabilityMinima{
				CaseSessionsPerFabric:  3,
				SubscriptionsPerFabric: 3,
			},
			SpecificationVersion: 0x01050000, // Matter 1.5
			MaxPathsPerInvoke:    1,
			SerialNumber:         &config.SerialNumber,
		},
	})
	ep.AddCluster(basicInfoCluster)

	// General Commissioning Cluster (0x0030) - Required
	// Manages commissioning state and fail-safe timer
	gcCluster := generalcommissioning.New(generalcommissioning.Config{
		EndpointID: RootEndpointID,
		// Default: all locations allowed
		LocationCapability: generalcommissioning.RegulatoryIndoorOutdoor,
	})
	ep.AddCluster(gcCluster)

	// TODO: Add these clusters when implemented:
	// - Network Commissioning (0x0031) - Required for Wi-Fi/Thread
	// - Operational Credentials (0x003E) - Required for certificate management
	// - Access Control (0x001F) - Required for ACL management
	// - Group Key Management (0x003F) - Required for group messaging
	// - ICD Management (0x0046) - Optional for sleepy devices

	return ep
}

// getVendorName returns a human-readable vendor name.
// For test vendors, returns a generic name. Real vendors would
// have their names in a lookup table.
func getVendorName(vendorID fabric.VendorID) string {
	switch vendorID {
	case 0xFFF1, 0xFFF2, 0xFFF3, 0xFFF4:
		return "Test Vendor"
	default:
		return "Unknown Vendor"
	}
}

// updateDescriptorCluster is a no-op since the descriptor cluster now queries
// the node directly for endpoint information. Kept for API compatibility.
func updateDescriptorCluster(node *datamodel.BasicNode, endpoints []*Endpoint) {
	// No-op: The descriptor cluster queries the node directly via its Node field
	// to get parts list, server list, etc. No manual updates needed.
}

// updateEndpointDescriptor ensures the endpoint has a descriptor cluster.
// If the endpoint doesn't have one, a descriptor cluster is added.
// The descriptor cluster will query the node directly for attribute values.
func updateEndpointDescriptor(ep *Endpoint, node datamodel.Node) {
	descriptorCluster := ep.GetCluster(descriptor.ClusterID)
	if descriptorCluster == nil {
		// Endpoint doesn't have a descriptor cluster - add one
		descCluster := descriptor.New(descriptor.Config{
			EndpointID: ep.ID(),
			Node:       node,
		})
		ep.AddCluster(descCluster)
	}
}
