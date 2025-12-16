package matter

import (
	"github.com/backkem/matter/pkg/datamodel"
)

// Endpoint wraps datamodel.BasicEndpoint with a fluent builder API.
// Use NewEndpoint to create an endpoint, then chain methods to configure it.
//
// Example:
//
//	ep := matter.NewEndpoint(1).
//	    WithDeviceType(0x0100, 1).  // On/Off Light
//	    AddCluster(onoff.NewServer())
type Endpoint struct {
	endpoint    *datamodel.BasicEndpoint
	deviceTypes []datamodel.DeviceTypeEntry
}

// NewEndpoint creates a new endpoint with the given ID.
// Endpoint 0 is reserved for the root endpoint and is created automatically.
func NewEndpoint(id datamodel.EndpointID) *Endpoint {
	return &Endpoint{
		endpoint:    datamodel.NewEndpoint(id),
		deviceTypes: make([]datamodel.DeviceTypeEntry, 0),
	}
}

// WithDeviceType adds a device type to the endpoint.
// A device type describes the device's functionality (e.g., 0x0100 = On/Off Light).
// Multiple device types can be added to a single endpoint.
//
// Common device types:
//   - 0x000E: Aggregator
//   - 0x000F: Bridged Node
//   - 0x0100: On/Off Light
//   - 0x0101: Dimmable Light
//   - 0x0103: On/Off Light Switch
//   - 0x010A: On/Off Plug-in Unit
//   - 0x0302: Temperature Sensor
//   - 0x0850: Camera
func (e *Endpoint) WithDeviceType(deviceType uint32, revision uint8) *Endpoint {
	e.deviceTypes = append(e.deviceTypes, datamodel.DeviceTypeEntry{
		DeviceTypeID: datamodel.DeviceTypeID(deviceType),
		Revision:     revision,
	})
	return e
}

// AddCluster adds a cluster implementation to the endpoint.
// The cluster must implement datamodel.Cluster.
func (e *Endpoint) AddCluster(cluster datamodel.Cluster) *Endpoint {
	e.endpoint.AddCluster(cluster)
	return e
}

// ID returns the endpoint ID.
func (e *Endpoint) ID() datamodel.EndpointID {
	return e.endpoint.ID()
}

// DeviceTypes returns the configured device types.
func (e *Endpoint) DeviceTypes() []datamodel.DeviceTypeEntry {
	return e.deviceTypes
}

// GetCluster returns a cluster by ID, or nil if not found.
func (e *Endpoint) GetCluster(id datamodel.ClusterID) datamodel.Cluster {
	return e.endpoint.GetCluster(id)
}

// GetClusters returns all clusters on this endpoint.
func (e *Endpoint) GetClusters() []datamodel.Cluster {
	return e.endpoint.GetClusters()
}

// Inner returns the underlying BasicEndpoint.
// Use this for advanced operations or passing to lower-level APIs.
func (e *Endpoint) Inner() *datamodel.BasicEndpoint {
	return e.endpoint
}
