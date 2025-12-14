package datamodel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"sync/atomic"

	"github.com/backkem/matter/pkg/tlv"
)

// ClusterBase provides common functionality for cluster implementations.
// Embed this struct in your cluster implementation to get standard behavior
// for global attributes and data version management.
type ClusterBase struct {
	id          ClusterID
	endpointID  EndpointID
	revision    uint16
	featureMap  uint32
	dataVersion atomic.Uint32
}

// NewClusterBase creates a new cluster base with the given parameters.
// The data version is initialized to a random value per Spec 7.10.3.
func NewClusterBase(id ClusterID, endpointID EndpointID, revision uint16) *ClusterBase {
	cb := &ClusterBase{
		id:         id,
		endpointID: endpointID,
		revision:   revision,
	}
	cb.dataVersion.Store(randomDataVersion())
	return cb
}

// ID returns the cluster ID.
func (c *ClusterBase) ID() ClusterID {
	return c.id
}

// EndpointID returns the endpoint this cluster belongs to.
func (c *ClusterBase) EndpointID() EndpointID {
	return c.endpointID
}

// ClusterRevision returns the cluster revision.
func (c *ClusterBase) ClusterRevision() uint16 {
	return c.revision
}

// FeatureMap returns the feature map.
func (c *ClusterBase) FeatureMap() uint32 {
	return c.featureMap
}

// DataVersion returns the current data version.
func (c *ClusterBase) DataVersion() DataVersion {
	return DataVersion(c.dataVersion.Load())
}

// SetFeatureMap sets the feature map bits.
func (c *ClusterBase) SetFeatureMap(features uint32) {
	c.featureMap = features
}

// IncrementDataVersion increments the data version.
// Call this whenever an attribute value changes.
func (c *ClusterBase) IncrementDataVersion() {
	c.dataVersion.Add(1)
}

// SetDataVersion sets the data version to a specific value.
// Use IncrementDataVersion for normal updates; this is for initialization.
func (c *ClusterBase) SetDataVersion(version DataVersion) {
	c.dataVersion.Store(uint32(version))
}

// Path returns the concrete cluster path for this cluster.
func (c *ClusterBase) Path() ConcreteClusterPath {
	return ConcreteClusterPath{
		Endpoint: c.endpointID,
		Cluster:  c.id,
	}
}

// AttributePath returns a concrete attribute path for an attribute on this cluster.
func (c *ClusterBase) AttributePath(attrID AttributeID) ConcreteAttributePath {
	return ConcreteAttributePath{
		Endpoint:  c.endpointID,
		Cluster:   c.id,
		Attribute: attrID,
	}
}

// CommandPath returns a concrete command path for a command on this cluster.
func (c *ClusterBase) CommandPath(cmdID CommandID) ConcreteCommandPath {
	return ConcreteCommandPath{
		Endpoint: c.endpointID,
		Cluster:  c.id,
		Command:  cmdID,
	}
}

// ReadGlobalAttribute handles reading of global attributes.
// Returns true if the attribute was handled, false if it's not a global attribute.
func (c *ClusterBase) ReadGlobalAttribute(ctx context.Context, attrID AttributeID, w *tlv.Writer, attrList []AttributeEntry, cmdList []CommandEntry, genCmdList []CommandID) (bool, error) {
	switch attrID {
	case GlobalAttrClusterRevision:
		return true, w.PutUint(tlv.Anonymous(), uint64(c.revision))

	case GlobalAttrFeatureMap:
		return true, w.PutUint(tlv.Anonymous(), uint64(c.featureMap))

	case GlobalAttrAttributeList:
		if err := w.StartArray(tlv.Anonymous()); err != nil {
			return true, err
		}
		for _, attr := range attrList {
			if err := w.PutUint(tlv.Anonymous(), uint64(attr.ID)); err != nil {
				return true, err
			}
		}
		return true, w.EndContainer()

	case GlobalAttrAcceptedCommandList:
		if err := w.StartArray(tlv.Anonymous()); err != nil {
			return true, err
		}
		for _, cmd := range cmdList {
			if err := w.PutUint(tlv.Anonymous(), uint64(cmd.ID)); err != nil {
				return true, err
			}
		}
		return true, w.EndContainer()

	case GlobalAttrGeneratedCommandList:
		if err := w.StartArray(tlv.Anonymous()); err != nil {
			return true, err
		}
		for _, cmdID := range genCmdList {
			if err := w.PutUint(tlv.Anonymous(), uint64(cmdID)); err != nil {
				return true, err
			}
		}
		return true, w.EndContainer()

	default:
		return false, nil
	}
}

// randomDataVersion generates a random initial data version.
func randomDataVersion() uint32 {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback to a fixed value if random fails
		return 1
	}
	return binary.LittleEndian.Uint32(buf[:])
}

// GlobalAttributeList returns the standard global attribute entries
// that should be included in every cluster's AttributeList.
func (c *ClusterBase) GlobalAttributeList() []AttributeEntry {
	return GlobalAttributeEntries()
}

// MergeAttributeLists combines cluster-specific attributes with global attributes.
// Use this to build the complete AttributeList for a cluster.
func MergeAttributeLists(clusterAttrs []AttributeEntry) []AttributeEntry {
	globals := GlobalAttributeEntries()
	result := make([]AttributeEntry, 0, len(clusterAttrs)+len(globals))
	result = append(result, clusterAttrs...)
	result = append(result, globals...)
	return result
}

// FindAttribute searches an attribute list for a specific attribute ID.
// Returns nil if not found.
func FindAttribute(list []AttributeEntry, id AttributeID) *AttributeEntry {
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	return nil
}

// FindCommand searches a command list for a specific command ID.
// Returns nil if not found.
func FindCommand(list []CommandEntry, id CommandID) *CommandEntry {
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	return nil
}
