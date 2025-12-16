package descriptor

import (
	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// readDeviceTypeList writes the DeviceTypeList attribute (0x0000).
// This is a list of DeviceTypeStruct entries describing the device types
// supported by this endpoint.
//
// Spec: Section 9.5.6.1
func (c *Cluster) readDeviceTypeList(w *tlv.Writer) error {
	endpoint := c.config.Node.GetEndpoint(c.config.EndpointID)
	if endpoint == nil {
		return datamodel.ErrEndpointNotFound
	}

	deviceTypes := endpoint.GetDeviceTypes()

	// Write as array
	if err := w.StartArray(tlv.Anonymous()); err != nil {
		return err
	}

	for _, dt := range deviceTypes {
		// DeviceTypeStruct: {deviceType: 0, revision: 1}
		if err := w.StartStructure(tlv.Anonymous()); err != nil {
			return err
		}
		if err := w.PutUint(tlv.ContextTag(0), uint64(dt.DeviceTypeID)); err != nil {
			return err
		}
		if err := w.PutUint(tlv.ContextTag(1), uint64(dt.Revision)); err != nil {
			return err
		}
		if err := w.EndContainer(); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// readServerList writes the ServerList attribute (0x0001).
// This is a list of cluster IDs for server clusters on this endpoint.
//
// Spec: Section 9.5.6.2
func (c *Cluster) readServerList(w *tlv.Writer) error {
	endpoint := c.config.Node.GetEndpoint(c.config.EndpointID)
	if endpoint == nil {
		return datamodel.ErrEndpointNotFound
	}

	clusters := endpoint.GetClusters()

	// Write as array of cluster IDs
	if err := w.StartArray(tlv.Anonymous()); err != nil {
		return err
	}

	for _, cluster := range clusters {
		if err := w.PutUint(tlv.Anonymous(), uint64(cluster.ID())); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// readClientList writes the ClientList attribute (0x0002).
// This is a list of cluster IDs for client clusters on this endpoint.
// For server-only implementations, this is typically empty.
//
// Spec: Section 9.5.6.3
func (c *Cluster) readClientList(w *tlv.Writer) error {
	// Server-only implementation - return empty array
	// In a full implementation, this would query client cluster metadata
	if err := w.StartArray(tlv.Anonymous()); err != nil {
		return err
	}
	return w.EndContainer()
}

// readPartsList writes the PartsList attribute (0x0003).
// This attribute indicates composition of the device type instance.
//
// For root endpoint (0): Returns ALL non-root endpoints.
// For other endpoints: Returns children based on composition pattern:
//   - kFullFamily: All descendants
//   - kTree: Only direct children
//
// Spec: Section 9.5.6.4
func (c *Cluster) readPartsList(w *tlv.Writer) error {
	endpoints := c.config.Node.GetEndpoints()

	if err := w.StartArray(tlv.Anonymous()); err != nil {
		return err
	}

	if c.config.EndpointID == 0 {
		// Root endpoint: return all non-root endpoints
		for _, ep := range endpoints {
			if ep.ID() != 0 {
				if err := w.PutUint(tlv.Anonymous(), uint64(ep.ID())); err != nil {
					return err
				}
			}
		}
	} else {
		// Non-root endpoint: return children based on composition pattern
		myEndpoint := c.config.Node.GetEndpoint(c.config.EndpointID)
		if myEndpoint == nil {
			return w.EndContainer()
		}

		entry := myEndpoint.Entry()

		switch entry.CompositionPattern {
		case datamodel.CompositionFullFamily:
			// All descendants - find all endpoints where we are an ancestor
			for _, ep := range endpoints {
				if c.isDescendantOf(ep.ID(), c.config.EndpointID, endpoints) {
					if err := w.PutUint(tlv.Anonymous(), uint64(ep.ID())); err != nil {
						return err
					}
				}
			}
		case datamodel.CompositionTree:
			// Direct children only
			for _, ep := range endpoints {
				epEntry := ep.Entry()
				if epEntry.ParentID != nil && *epEntry.ParentID == c.config.EndpointID {
					if err := w.PutUint(tlv.Anonymous(), uint64(ep.ID())); err != nil {
						return err
					}
				}
			}
		}
	}

	return w.EndContainer()
}

// isDescendantOf checks if childID is a descendant of parentID.
func (c *Cluster) isDescendantOf(childID, parentID datamodel.EndpointID, endpoints []datamodel.Endpoint) bool {
	if childID == parentID {
		return false // Not a descendant of itself
	}

	// Walk up the parent chain
	currentID := childID
	for {
		var currentEntry *datamodel.EndpointEntry
		for _, ep := range endpoints {
			if ep.ID() == currentID {
				entry := ep.Entry()
				currentEntry = &entry
				break
			}
		}

		if currentEntry == nil {
			return false // Endpoint not found
		}

		if currentEntry.ParentID == nil {
			return false // Reached root without finding parent
		}

		if *currentEntry.ParentID == parentID {
			return true // Found the parent
		}

		currentID = *currentEntry.ParentID
	}
}

// readTagList writes the TagList attribute (0x0004).
// This is a list of SemanticTagStruct entries for endpoint disambiguation.
//
// Spec: Section 9.5.6.5
func (c *Cluster) readTagList(w *tlv.Writer) error {
	if len(c.config.SemanticTags) == 0 {
		return datamodel.ErrUnsupportedAttribute
	}

	if err := w.StartArray(tlv.Anonymous()); err != nil {
		return err
	}

	for _, tag := range c.config.SemanticTags {
		// SemanticTagStruct: {mfgCode: 0, namespaceID: 1, tag: 2, label: 3}
		if err := w.StartStructure(tlv.Anonymous()); err != nil {
			return err
		}

		// MfgCode (nullable)
		if tag.MfgCode != nil {
			if err := w.PutUint(tlv.ContextTag(0), uint64(*tag.MfgCode)); err != nil {
				return err
			}
		} else {
			if err := w.PutNull(tlv.ContextTag(0)); err != nil {
				return err
			}
		}

		if err := w.PutUint(tlv.ContextTag(1), uint64(tag.NamespaceID)); err != nil {
			return err
		}
		if err := w.PutUint(tlv.ContextTag(2), uint64(tag.Tag)); err != nil {
			return err
		}

		// Label (optional)
		if tag.Label != nil {
			if err := w.PutString(tlv.ContextTag(3), *tag.Label); err != nil {
				return err
			}
		}

		if err := w.EndContainer(); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// readEndpointUniqueID writes the EndpointUniqueID attribute (0x0005).
// This is an optional unique identifier for the endpoint.
//
// Spec: Section 9.5.6.6
func (c *Cluster) readEndpointUniqueID(w *tlv.Writer) error {
	if c.config.EndpointUniqueID == nil {
		return datamodel.ErrUnsupportedAttribute
	}

	return w.PutString(tlv.Anonymous(), *c.config.EndpointUniqueID)
}
