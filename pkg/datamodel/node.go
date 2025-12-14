package datamodel

import "sync"

// BasicNode is a simple in-memory Node implementation.
// It provides thread-safe endpoint registration and lookup.
type BasicNode struct {
	mu        sync.RWMutex
	endpoints map[EndpointID]Endpoint
	order     []EndpointID // Preserve registration order
	listener  AttributeChangeListener
}

// NewNode creates a new empty node.
func NewNode() *BasicNode {
	return &BasicNode{
		endpoints: make(map[EndpointID]Endpoint),
	}
}

// AddEndpoint registers an endpoint with the node.
// Returns ErrEndpointExists if an endpoint with the same ID already exists.
func (n *BasicNode) AddEndpoint(ep Endpoint) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := ep.ID()
	if _, exists := n.endpoints[id]; exists {
		return ErrEndpointExists
	}

	n.endpoints[id] = ep
	n.order = append(n.order, id)
	return nil
}

// RemoveEndpoint removes an endpoint from the node.
// Returns ErrEndpointNotFound if the endpoint doesn't exist.
func (n *BasicNode) RemoveEndpoint(id EndpointID) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if _, exists := n.endpoints[id]; !exists {
		return ErrEndpointNotFound
	}

	delete(n.endpoints, id)

	// Remove from order slice
	for i, epID := range n.order {
		if epID == id {
			n.order = append(n.order[:i], n.order[i+1:]...)
			break
		}
	}

	return nil
}

// GetEndpoint returns the endpoint with the given ID, or nil if not found.
func (n *BasicNode) GetEndpoint(id EndpointID) Endpoint {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.endpoints[id]
}

// GetEndpoints returns all endpoints in registration order.
func (n *BasicNode) GetEndpoints() []Endpoint {
	n.mu.RLock()
	defer n.mu.RUnlock()

	result := make([]Endpoint, 0, len(n.order))
	for _, id := range n.order {
		if ep, ok := n.endpoints[id]; ok {
			result = append(result, ep)
		}
	}
	return result
}

// EndpointCount returns the number of registered endpoints.
func (n *BasicNode) EndpointCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.endpoints)
}

// HasEndpoint returns true if an endpoint with the given ID exists.
func (n *BasicNode) HasEndpoint(id EndpointID) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	_, exists := n.endpoints[id]
	return exists
}

// SetAttributeChangeListener sets the listener for attribute changes.
func (n *BasicNode) SetAttributeChangeListener(listener AttributeChangeListener) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.listener = listener
}

// NotifyAttributeChanged notifies the listener that an attribute changed.
// This should be called by clusters when attributes are modified.
func (n *BasicNode) NotifyAttributeChanged(path ConcreteAttributePath) {
	n.mu.RLock()
	listener := n.listener
	n.mu.RUnlock()

	if listener != nil {
		listener.OnAttributeChanged(path)
	}
}

// GetCluster is a convenience method to get a cluster by endpoint and cluster ID.
// Returns nil if the endpoint or cluster doesn't exist.
func (n *BasicNode) GetCluster(endpointID EndpointID, clusterID ClusterID) Cluster {
	ep := n.GetEndpoint(endpointID)
	if ep == nil {
		return nil
	}
	return ep.GetCluster(clusterID)
}

// Verify BasicNode implements the interfaces.
var (
	_ Node              = (*BasicNode)(nil)
	_ DataModelProvider = (*BasicNode)(nil)
)
