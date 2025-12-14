package datamodel

import "sync"

// BasicEndpoint is a simple in-memory Endpoint implementation.
// It provides thread-safe cluster registration and lookup.
type BasicEndpoint struct {
	mu          sync.RWMutex
	entry       EndpointEntry
	clusters    map[ClusterID]Cluster
	order       []ClusterID // Preserve registration order
	deviceTypes []DeviceTypeEntry
}

// NewEndpoint creates a new endpoint with the given ID.
// The endpoint uses Tree composition pattern by default.
func NewEndpoint(id EndpointID) *BasicEndpoint {
	return &BasicEndpoint{
		entry: EndpointEntry{
			ID:                 id,
			CompositionPattern: CompositionTree,
		},
		clusters: make(map[ClusterID]Cluster),
	}
}

// NewEndpointWithParent creates a new endpoint with the given ID and parent.
func NewEndpointWithParent(id EndpointID, parentID EndpointID) *BasicEndpoint {
	ep := NewEndpoint(id)
	ep.entry.ParentID = &parentID
	return ep
}

// ID returns the endpoint ID.
func (e *BasicEndpoint) ID() EndpointID {
	return e.entry.ID
}

// Entry returns the endpoint metadata.
func (e *BasicEndpoint) Entry() EndpointEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.entry
}

// SetParent sets the parent endpoint ID.
func (e *BasicEndpoint) SetParent(parentID EndpointID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.entry.ParentID = &parentID
}

// SetCompositionPattern sets the endpoint composition pattern.
func (e *BasicEndpoint) SetCompositionPattern(pattern EndpointComposition) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.entry.CompositionPattern = pattern
}

// AddCluster registers a cluster with the endpoint.
// Returns ErrClusterExists if a cluster with the same ID already exists.
func (e *BasicEndpoint) AddCluster(c Cluster) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	id := c.ID()
	if _, exists := e.clusters[id]; exists {
		return ErrClusterExists
	}

	e.clusters[id] = c
	e.order = append(e.order, id)
	return nil
}

// RemoveCluster removes a cluster from the endpoint.
// Returns ErrClusterNotFound if the cluster doesn't exist.
func (e *BasicEndpoint) RemoveCluster(id ClusterID) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.clusters[id]; !exists {
		return ErrClusterNotFound
	}

	delete(e.clusters, id)

	// Remove from order slice
	for i, cID := range e.order {
		if cID == id {
			e.order = append(e.order[:i], e.order[i+1:]...)
			break
		}
	}

	return nil
}

// GetCluster returns the cluster with the given ID, or nil if not found.
func (e *BasicEndpoint) GetCluster(id ClusterID) Cluster {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.clusters[id]
}

// GetClusters returns all clusters in registration order.
func (e *BasicEndpoint) GetClusters() []Cluster {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]Cluster, 0, len(e.order))
	for _, id := range e.order {
		if c, ok := e.clusters[id]; ok {
			result = append(result, c)
		}
	}
	return result
}

// ClusterCount returns the number of registered clusters.
func (e *BasicEndpoint) ClusterCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.clusters)
}

// HasCluster returns true if a cluster with the given ID exists.
func (e *BasicEndpoint) HasCluster(id ClusterID) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, exists := e.clusters[id]
	return exists
}

// AddDeviceType adds a device type to the endpoint.
func (e *BasicEndpoint) AddDeviceType(dt DeviceTypeEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deviceTypes = append(e.deviceTypes, dt)
}

// GetDeviceTypes returns all device types for this endpoint.
func (e *BasicEndpoint) GetDeviceTypes() []DeviceTypeEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]DeviceTypeEntry{}, e.deviceTypes...)
}

// ClearDeviceTypes removes all device types from the endpoint.
func (e *BasicEndpoint) ClearDeviceTypes() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deviceTypes = nil
}

// GetClusterIDs returns the IDs of all clusters on this endpoint.
func (e *BasicEndpoint) GetClusterIDs() []ClusterID {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]ClusterID{}, e.order...)
}

// Verify BasicEndpoint implements the interface.
var _ Endpoint = (*BasicEndpoint)(nil)
