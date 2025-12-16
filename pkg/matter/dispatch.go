package matter

import (
	"context"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/im"
	imsg "github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/tlv"
)

// nodeDispatcher implements im.Dispatcher by routing to the datamodel.
type nodeDispatcher struct {
	node *datamodel.BasicNode
}

// newNodeDispatcher creates a dispatcher that routes to the given node's data model.
func newNodeDispatcher(node *datamodel.BasicNode) *nodeDispatcher {
	return &nodeDispatcher{node: node}
}

// ReadAttribute reads an attribute value.
func (d *nodeDispatcher) ReadAttribute(ctx context.Context, req *im.AttributeReadRequest, w *tlv.Writer) error {
	// Get endpoint (handle nil pointer)
	endpointID := datamodel.EndpointID(0)
	if req.Path.Endpoint != nil {
		endpointID = datamodel.EndpointID(*req.Path.Endpoint)
	}

	endpoint := d.node.GetEndpoint(endpointID)
	if endpoint == nil {
		return im.ErrClusterNotFound
	}

	// Get cluster (handle nil pointer)
	clusterID := datamodel.ClusterID(0)
	if req.Path.Cluster != nil {
		clusterID = datamodel.ClusterID(*req.Path.Cluster)
	}

	cluster := endpoint.GetCluster(clusterID)
	if cluster == nil {
		return im.ErrClusterNotFound
	}

	// Read the attribute using the cluster's ReadAttribute method
	attrID := datamodel.AttributeID(0)
	if req.Path.Attribute != nil {
		attrID = datamodel.AttributeID(*req.Path.Attribute)
	}

	// Build a ReadAttributeRequest for the cluster
	readReq := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  endpointID,
			Cluster:   clusterID,
			Attribute: attrID,
		},
	}

	return cluster.ReadAttribute(ctx, readReq, w)
}

// WriteAttribute writes an attribute value.
func (d *nodeDispatcher) WriteAttribute(ctx context.Context, req *im.AttributeWriteRequest, r *tlv.Reader) error {
	// Get endpoint (handle nil pointer)
	endpointID := datamodel.EndpointID(0)
	if req.Path.Endpoint != nil {
		endpointID = datamodel.EndpointID(*req.Path.Endpoint)
	}

	endpoint := d.node.GetEndpoint(endpointID)
	if endpoint == nil {
		return im.ErrClusterNotFound
	}

	// Get cluster (handle nil pointer)
	clusterID := datamodel.ClusterID(0)
	if req.Path.Cluster != nil {
		clusterID = datamodel.ClusterID(*req.Path.Cluster)
	}

	cluster := endpoint.GetCluster(clusterID)
	if cluster == nil {
		return im.ErrClusterNotFound
	}

	// Write the attribute using the cluster's WriteAttribute method
	attrID := datamodel.AttributeID(0)
	if req.Path.Attribute != nil {
		attrID = datamodel.AttributeID(*req.Path.Attribute)
	}

	// Build a WriteAttributeRequest for the cluster
	writeReq := datamodel.WriteAttributeRequest{
		Path: datamodel.ConcreteDataAttributePath{
			ConcreteAttributePath: datamodel.ConcreteAttributePath{
				Endpoint:  endpointID,
				Cluster:   clusterID,
				Attribute: attrID,
			},
		},
	}

	return cluster.WriteAttribute(ctx, writeReq, r)
}

// InvokeCommand invokes a cluster command.
func (d *nodeDispatcher) InvokeCommand(ctx context.Context, req *im.CommandInvokeRequest, r *tlv.Reader) ([]byte, error) {
	// Get endpoint
	endpoint := d.node.GetEndpoint(datamodel.EndpointID(req.Path.Endpoint))
	if endpoint == nil {
		return nil, im.ErrClusterNotFound
	}

	// Get cluster
	cluster := endpoint.GetCluster(datamodel.ClusterID(req.Path.Cluster))
	if cluster == nil {
		return nil, im.ErrClusterNotFound
	}

	// Build an InvokeRequest for the cluster
	invokeReq := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: datamodel.EndpointID(req.Path.Endpoint),
			Cluster:  datamodel.ClusterID(req.Path.Cluster),
			Command:  datamodel.CommandID(req.Path.Command),
		},
	}

	return cluster.InvokeCommand(ctx, invokeReq, r)
}

// Verify nodeDispatcher implements im.Dispatcher.
var _ im.Dispatcher = (*nodeDispatcher)(nil)

// StatusError wraps an IM status code as an error.
type StatusError struct {
	Status imsg.Status
}

func (e *StatusError) Error() string {
	return e.Status.String()
}

// NewStatusError creates a new StatusError.
func NewStatusError(status imsg.Status) *StatusError {
	return &StatusError{Status: status}
}
