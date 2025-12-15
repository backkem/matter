package datamodel

import (
	"context"
	"sync"

	"github.com/backkem/matter/pkg/tlv"
)

// Router provides a simple registry for routing IM operations to clusters.
// It implements a map-based lookup: EndpointID → ClusterID → Cluster.
//
// This is a minimal implementation for commissioning support.
// For production use, consider using the full Node/Endpoint/Cluster hierarchy.
type Router struct {
	// endpoints maps endpoint ID to a map of clusters
	endpoints map[EndpointID]map[ClusterID]Cluster

	mu sync.RWMutex
}

// NewRouter creates a new router.
func NewRouter() *Router {
	return &Router{
		endpoints: make(map[EndpointID]map[ClusterID]Cluster),
	}
}

// RegisterCluster registers a cluster at a specific endpoint.
func (r *Router) RegisterCluster(endpointID EndpointID, cluster Cluster) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.endpoints[endpointID] == nil {
		r.endpoints[endpointID] = make(map[ClusterID]Cluster)
	}
	r.endpoints[endpointID][cluster.ID()] = cluster
}

// UnregisterCluster removes a cluster from an endpoint.
func (r *Router) UnregisterCluster(endpointID EndpointID, clusterID ClusterID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.endpoints[endpointID] != nil {
		delete(r.endpoints[endpointID], clusterID)
		if len(r.endpoints[endpointID]) == 0 {
			delete(r.endpoints, endpointID)
		}
	}
}

// GetCluster looks up a cluster by endpoint and cluster ID.
func (r *Router) GetCluster(endpointID EndpointID, clusterID ClusterID) (Cluster, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	clusters, ok := r.endpoints[endpointID]
	if !ok {
		return nil, ErrEndpointNotFound
	}

	cluster, ok := clusters[clusterID]
	if !ok {
		return nil, ErrClusterNotFound
	}

	return cluster, nil
}

// GetEndpointClusters returns all clusters on an endpoint.
func (r *Router) GetEndpointClusters(endpointID EndpointID) []Cluster {
	r.mu.RLock()
	defer r.mu.RUnlock()

	clusters, ok := r.endpoints[endpointID]
	if !ok {
		return nil
	}

	result := make([]Cluster, 0, len(clusters))
	for _, c := range clusters {
		result = append(result, c)
	}
	return result
}

// GetEndpointIDs returns all registered endpoint IDs.
func (r *Router) GetEndpointIDs() []EndpointID {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]EndpointID, 0, len(r.endpoints))
	for id := range r.endpoints {
		result = append(result, id)
	}
	return result
}

// ReadAttribute reads an attribute from the appropriate cluster.
func (r *Router) ReadAttribute(ctx context.Context, req ReadAttributeRequest, w *tlv.Writer) error {
	cluster, err := r.GetCluster(req.Path.Endpoint, req.Path.Cluster)
	if err != nil {
		return err
	}

	return cluster.ReadAttribute(ctx, req, w)
}

// WriteAttribute writes an attribute to the appropriate cluster.
func (r *Router) WriteAttribute(ctx context.Context, req WriteAttributeRequest, reader *tlv.Reader) error {
	cluster, err := r.GetCluster(req.Path.Endpoint, req.Path.Cluster)
	if err != nil {
		return err
	}

	return cluster.WriteAttribute(ctx, req, reader)
}

// InvokeCommand invokes a command on the appropriate cluster.
func (r *Router) InvokeCommand(ctx context.Context, req InvokeRequest, reader *tlv.Reader) ([]byte, error) {
	cluster, err := r.GetCluster(req.Path.Endpoint, req.Path.Cluster)
	if err != nil {
		return nil, err
	}

	return cluster.InvokeCommand(ctx, req, reader)
}

// RouterNode wraps a Router to implement the Node interface.
// This allows the Router to be used where a Node is expected.
type RouterNode struct {
	router *Router
}

// NewRouterNode creates a Node implementation backed by a Router.
func NewRouterNode(router *Router) *RouterNode {
	return &RouterNode{router: router}
}

// GetEndpoint returns an endpoint by ID.
func (n *RouterNode) GetEndpoint(id EndpointID) Endpoint {
	clusters := n.router.GetEndpointClusters(id)
	if len(clusters) == 0 {
		return nil
	}
	return &routerEndpoint{
		id:       id,
		clusters: clusters,
	}
}

// GetEndpoints returns all endpoints.
func (n *RouterNode) GetEndpoints() []Endpoint {
	ids := n.router.GetEndpointIDs()
	endpoints := make([]Endpoint, 0, len(ids))
	for _, id := range ids {
		if ep := n.GetEndpoint(id); ep != nil {
			endpoints = append(endpoints, ep)
		}
	}
	return endpoints
}

// routerEndpoint implements Endpoint for RouterNode.
type routerEndpoint struct {
	id       EndpointID
	clusters []Cluster
}

func (e *routerEndpoint) ID() EndpointID {
	return e.id
}

func (e *routerEndpoint) Entry() EndpointEntry {
	return EndpointEntry{
		ID: e.id,
	}
}

func (e *routerEndpoint) GetCluster(id ClusterID) Cluster {
	for _, c := range e.clusters {
		if c.ID() == id {
			return c
		}
	}
	return nil
}

func (e *routerEndpoint) GetClusters() []Cluster {
	return e.clusters
}

func (e *routerEndpoint) GetDeviceTypes() []DeviceTypeEntry {
	return nil // Not tracked by simple router
}
