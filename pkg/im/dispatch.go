package im

import (
	"context"

	"github.com/backkem/matter/pkg/acl"
	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/tlv"
)

// Dispatcher routes IM operations to cluster implementations.
// This is the bridge between the IM engine and the data model.
type Dispatcher interface {
	// ReadAttribute reads an attribute value.
	// Returns error if the cluster/attribute doesn't exist or access denied.
	ReadAttribute(ctx context.Context, req *AttributeReadRequest, w *tlv.Writer) error

	// WriteAttribute writes an attribute value.
	// Returns error if the cluster/attribute doesn't exist, access denied, or constraint violation.
	WriteAttribute(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error

	// InvokeCommand invokes a cluster command.
	// Returns response TLV data (may be nil) and error.
	InvokeCommand(ctx context.Context, req *CommandInvokeRequest, r *tlv.Reader) ([]byte, error)
}

// AttributeReadRequest contains parameters for reading an attribute via IM.
type AttributeReadRequest struct {
	// Path identifies the attribute to read.
	Path message.AttributePathIB

	// IMContext is the IM request context.
	IMContext *RequestContext

	// IsFabricFiltered indicates fabric-filtered read.
	IsFabricFiltered bool
}

// ToDataModelRequest converts to a datamodel.ReadAttributeRequest.
func (r *AttributeReadRequest) ToDataModelRequest() datamodel.ReadAttributeRequest {
	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  derefEndpoint(r.Path.Endpoint),
			Cluster:   derefCluster(r.Path.Cluster),
			Attribute: derefAttribute(r.Path.Attribute),
		},
	}

	if r.IsFabricFiltered {
		req.ReadFlags |= datamodel.ReadFlagFabricFiltered
	}

	if r.IMContext != nil {
		req.Subject = &datamodel.SubjectDescriptor{
			FabricIndex: r.IMContext.Subject.FabricIndex,
			NodeID:      r.IMContext.Subject.Subject,
			AuthMode:    toDataModelAuthMode(r.IMContext.Subject.AuthMode),
		}
	}

	return req
}

// AttributeWriteRequest contains parameters for writing an attribute via IM.
type AttributeWriteRequest struct {
	// Path identifies the attribute to write.
	Path message.AttributePathIB

	// IMContext is the IM request context.
	IMContext *RequestContext

	// IsTimed indicates this is a timed write.
	IsTimed bool

	// DataVersion is the expected data version (nil = no check).
	DataVersion *message.DataVersion
}

// ToDataModelRequest converts to a datamodel.WriteAttributeRequest.
func (r *AttributeWriteRequest) ToDataModelRequest() datamodel.WriteAttributeRequest {
	req := datamodel.WriteAttributeRequest{
		Path: datamodel.ConcreteDataAttributePath{
			ConcreteAttributePath: datamodel.ConcreteAttributePath{
				Endpoint:  derefEndpoint(r.Path.Endpoint),
				Cluster:   derefCluster(r.Path.Cluster),
				Attribute: derefAttribute(r.Path.Attribute),
			},
			ListIndex: r.Path.ListIndex,
		},
		DataVersion: r.DataVersion,
	}

	if r.IsTimed {
		req.WriteFlags |= datamodel.WriteFlagTimed
	}

	if r.IMContext != nil {
		req.Subject = &datamodel.SubjectDescriptor{
			FabricIndex: r.IMContext.Subject.FabricIndex,
			NodeID:      r.IMContext.Subject.Subject,
			AuthMode:    toDataModelAuthMode(r.IMContext.Subject.AuthMode),
		}
	}

	return req
}

// CommandInvokeRequest contains parameters for invoking a command via IM.
type CommandInvokeRequest struct {
	// Path identifies the command to invoke.
	Path message.CommandPathIB

	// IMContext is the IM request context.
	IMContext *RequestContext

	// IsTimed indicates this is a timed invoke.
	IsTimed bool
}

// ToDataModelRequest converts to a datamodel.InvokeRequest.
func (r *CommandInvokeRequest) ToDataModelRequest() datamodel.InvokeRequest {
	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: datamodel.EndpointID(r.Path.Endpoint),
			Cluster:  datamodel.ClusterID(r.Path.Cluster),
			Command:  datamodel.CommandID(r.Path.Command),
		},
	}

	if r.IsTimed {
		req.InvokeFlags |= datamodel.InvokeFlagTimed
	}

	if r.IMContext != nil {
		req.Subject = &datamodel.SubjectDescriptor{
			FabricIndex: r.IMContext.Subject.FabricIndex,
			NodeID:      r.IMContext.Subject.Subject,
			AuthMode:    toDataModelAuthMode(r.IMContext.Subject.AuthMode),
		}
	}

	return req
}

// Helper functions for dereferencing optional path fields.
func derefEndpoint(p *message.EndpointID) datamodel.EndpointID {
	if p == nil {
		return 0
	}
	return datamodel.EndpointID(*p)
}

func derefCluster(p *message.ClusterID) datamodel.ClusterID {
	if p == nil {
		return 0
	}
	return datamodel.ClusterID(*p)
}

func derefAttribute(p *message.AttributeID) datamodel.AttributeID {
	if p == nil {
		return 0
	}
	return datamodel.AttributeID(*p)
}

// toDataModelAuthMode converts ACL auth mode to datamodel auth mode.
func toDataModelAuthMode(m acl.AuthMode) datamodel.AuthMode {
	switch m {
	case acl.AuthModeCASE:
		return datamodel.AuthModeCASE
	case acl.AuthModePASE:
		return datamodel.AuthModePASE
	case acl.AuthModeGroup:
		return datamodel.AuthModeGroup
	default:
		return datamodel.AuthModeUnknown
	}
}

// NullDispatcher is a dispatcher that returns UnsupportedCluster for all operations.
// Use as a placeholder when no data model is available.
type NullDispatcher struct{}

// ReadAttribute always returns ErrClusterNotFound.
func (NullDispatcher) ReadAttribute(ctx context.Context, req *AttributeReadRequest, w *tlv.Writer) error {
	return ErrClusterNotFound
}

// WriteAttribute always returns ErrClusterNotFound.
func (NullDispatcher) WriteAttribute(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error {
	return ErrClusterNotFound
}

// InvokeCommand always returns ErrClusterNotFound.
func (NullDispatcher) InvokeCommand(ctx context.Context, req *CommandInvokeRequest, r *tlv.Reader) ([]byte, error) {
	return nil, ErrClusterNotFound
}
