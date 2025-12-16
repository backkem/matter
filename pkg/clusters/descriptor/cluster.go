// Package descriptor implements the Descriptor Cluster (0x001D).
//
// The Descriptor cluster describes an endpoint's device types, server/client
// clusters, and composition (PartsList). It's mandatory on all endpoints.
//
// Spec Reference: Section 9.5
//
// C++ Reference: src/app/clusters/descriptor/DescriptorCluster.cpp
package descriptor

import (
	"context"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// Cluster constants.
const (
	ClusterID       datamodel.ClusterID = 0x001D
	ClusterRevision uint16              = 3
)

// Attribute IDs (Spec 9.5.6).
const (
	AttrDeviceTypeList   datamodel.AttributeID = 0x0000
	AttrServerList       datamodel.AttributeID = 0x0001
	AttrClientList       datamodel.AttributeID = 0x0002
	AttrPartsList        datamodel.AttributeID = 0x0003
	AttrTagList          datamodel.AttributeID = 0x0004
	AttrEndpointUniqueID datamodel.AttributeID = 0x0005
)

// Feature bits (Spec 9.5.4).
type Feature uint32

const (
	// FeatureTagList indicates the TagList attribute is present.
	FeatureTagList Feature = 1 << 0 // TAGLIST
)

// SemanticTag represents a semantic tag for endpoint disambiguation (Spec 9.5.6.5).
type SemanticTag struct {
	// MfgCode is the manufacturer code (null for standard tags).
	MfgCode *uint16

	// NamespaceID identifies the namespace for the tag.
	NamespaceID uint8

	// Tag is the semantic tag value within the namespace.
	Tag uint8

	// Label is an optional human-readable label.
	Label *string
}

// Config provides dependencies for the Descriptor cluster.
type Config struct {
	// EndpointID is the endpoint this cluster belongs to.
	EndpointID datamodel.EndpointID

	// Node provides access to endpoint/cluster information.
	// The cluster queries this to build ServerList, ClientList, and PartsList.
	Node datamodel.Node

	// SemanticTags provides optional semantic tags for this endpoint.
	// If non-empty, the TAGLIST feature is enabled.
	SemanticTags []SemanticTag

	// EndpointUniqueID is an optional unique identifier for the endpoint.
	EndpointUniqueID *string
}

// Cluster implements the Descriptor cluster (0x001D).
type Cluster struct {
	*datamodel.ClusterBase
	config Config

	// Cached attribute list (built on construction).
	attrList []datamodel.AttributeEntry
}

// New creates a new Descriptor cluster.
func New(cfg Config) *Cluster {
	c := &Cluster{
		ClusterBase: datamodel.NewClusterBase(ClusterID, cfg.EndpointID, ClusterRevision),
		config:      cfg,
	}

	// Set feature map based on config.
	var features uint32
	if len(cfg.SemanticTags) > 0 {
		features |= uint32(FeatureTagList)
	}
	c.SetFeatureMap(features)

	// Build attribute list.
	c.attrList = c.buildAttributeList()

	return c
}

// buildAttributeList constructs the list of supported attributes.
func (c *Cluster) buildAttributeList() []datamodel.AttributeEntry {
	viewPriv := datamodel.PrivilegeView

	attrs := []datamodel.AttributeEntry{
		// Mandatory attributes
		datamodel.NewReadOnlyAttribute(AttrDeviceTypeList, datamodel.AttrQualityList|datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrServerList, datamodel.AttrQualityList|datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrClientList, datamodel.AttrQualityList|datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrPartsList, datamodel.AttrQualityList, viewPriv),
	}

	// Optional: TagList (if TAGLIST feature enabled)
	if len(c.config.SemanticTags) > 0 {
		attrs = append(attrs, datamodel.NewReadOnlyAttribute(AttrTagList, datamodel.AttrQualityList|datamodel.AttrQualityFixed, viewPriv))
	}

	// Optional: EndpointUniqueID
	if c.config.EndpointUniqueID != nil {
		attrs = append(attrs, datamodel.NewReadOnlyAttribute(AttrEndpointUniqueID, datamodel.AttrQualityFixed, viewPriv))
	}

	// Add global attributes
	return datamodel.MergeAttributeLists(attrs)
}

// AttributeList implements datamodel.Cluster.
func (c *Cluster) AttributeList() []datamodel.AttributeEntry {
	return c.attrList
}

// AcceptedCommandList implements datamodel.Cluster.
// Descriptor cluster has no commands.
func (c *Cluster) AcceptedCommandList() []datamodel.CommandEntry {
	return nil
}

// GeneratedCommandList implements datamodel.Cluster.
// Descriptor cluster has no commands.
func (c *Cluster) GeneratedCommandList() []datamodel.CommandID {
	return nil
}

// ReadAttribute implements datamodel.Cluster.
func (c *Cluster) ReadAttribute(ctx context.Context, req datamodel.ReadAttributeRequest, w *tlv.Writer) error {
	// Handle global attributes first
	handled, err := c.ReadGlobalAttribute(ctx, req.Path.Attribute, w, c.attrList, nil, nil)
	if handled || err != nil {
		return err
	}

	switch req.Path.Attribute {
	case AttrDeviceTypeList:
		return c.readDeviceTypeList(w)
	case AttrServerList:
		return c.readServerList(w)
	case AttrClientList:
		return c.readClientList(w)
	case AttrPartsList:
		return c.readPartsList(w)
	case AttrTagList:
		return c.readTagList(w)
	case AttrEndpointUniqueID:
		return c.readEndpointUniqueID(w)
	default:
		return datamodel.ErrUnsupportedAttribute
	}
}

// WriteAttribute implements datamodel.Cluster.
// Descriptor cluster has no writable attributes.
func (c *Cluster) WriteAttribute(ctx context.Context, req datamodel.WriteAttributeRequest, r *tlv.Reader) error {
	return datamodel.ErrUnsupportedWrite
}

// InvokeCommand implements datamodel.Cluster.
// Descriptor cluster has no commands.
func (c *Cluster) InvokeCommand(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	return nil, datamodel.ErrUnsupportedCommand
}
