package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// AttributePathIB identifies an attribute or set of attributes.
// Spec: Section 10.6.2
// Container type: List
type AttributePathIB struct {
	EnableTagCompression *bool        // Tag 0
	Node                 *NodeID      // Tag 1
	Endpoint             *EndpointID  // Tag 2
	Cluster              *ClusterID   // Tag 3
	Attribute            *AttributeID // Tag 4
	ListIndex            *ListIndex   // Tag 5 (nullable)
}

// Context tags for AttributePathIB.
const (
	attrPathTagEnableTagCompression = 0
	attrPathTagNode                 = 1
	attrPathTagEndpoint             = 2
	attrPathTagCluster              = 3
	attrPathTagAttribute            = 4
	attrPathTagListIndex            = 5
)

// Encode writes the AttributePathIB to the TLV writer.
func (p *AttributePathIB) Encode(w *tlv.Writer) error {
	return p.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the AttributePathIB with a specific tag.
func (p *AttributePathIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartList(tag); err != nil {
		return err
	}

	if p.EnableTagCompression != nil {
		if err := w.PutBool(tlv.ContextTag(attrPathTagEnableTagCompression), *p.EnableTagCompression); err != nil {
			return err
		}
	}

	if p.Node != nil {
		if err := w.PutUint(tlv.ContextTag(attrPathTagNode), uint64(*p.Node)); err != nil {
			return err
		}
	}

	if p.Endpoint != nil {
		if err := w.PutUint(tlv.ContextTag(attrPathTagEndpoint), uint64(*p.Endpoint)); err != nil {
			return err
		}
	}

	if p.Cluster != nil {
		if err := w.PutUint(tlv.ContextTag(attrPathTagCluster), uint64(*p.Cluster)); err != nil {
			return err
		}
	}

	if p.Attribute != nil {
		if err := w.PutUint(tlv.ContextTag(attrPathTagAttribute), uint64(*p.Attribute)); err != nil {
			return err
		}
	}

	if p.ListIndex != nil {
		if err := w.PutUint(tlv.ContextTag(attrPathTagListIndex), uint64(*p.ListIndex)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads an AttributePathIB from the TLV reader.
// The reader must be positioned at the start of the List container.
func (p *AttributePathIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeList {
		return ErrInvalidType
	}

	if err := r.EnterContainer(); err != nil {
		return err
	}

	for {
		if err := r.Next(); err != nil {
			if err == io.EOF || r.IsEndOfContainer() {
				break
			}
			return err
		}

		if r.IsEndOfContainer() {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			if err := r.Skip(); err != nil {
				return err
			}
			continue
		}

		switch tag.TagNumber() {
		case attrPathTagEnableTagCompression:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			p.EnableTagCompression = &v

		case attrPathTagNode:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			nodeID := NodeID(v)
			p.Node = &nodeID

		case attrPathTagEndpoint:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			endpointID := EndpointID(v)
			p.Endpoint = &endpointID

		case attrPathTagCluster:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			clusterID := ClusterID(v)
			p.Cluster = &clusterID

		case attrPathTagAttribute:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			attributeID := AttributeID(v)
			p.Attribute = &attributeID

		case attrPathTagListIndex:
			// ListIndex can be null or a value
			if r.Type() == tlv.ElementTypeNull {
				// Null means "all items" - represented as nil
				p.ListIndex = nil
			} else {
				v, err := r.Uint()
				if err != nil {
					return err
				}
				listIndex := ListIndex(v)
				p.ListIndex = &listIndex
			}

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	return r.ExitContainer()
}

// DecodeFrom reads an AttributePathIB assuming the reader has already
// consumed the container start. Used when decoding from arrays.
func (p *AttributePathIB) DecodeFrom(r *tlv.Reader) error {
	if err := r.EnterContainer(); err != nil {
		return err
	}

	for {
		if err := r.Next(); err != nil {
			if err == io.EOF || r.IsEndOfContainer() {
				break
			}
			return err
		}

		if r.IsEndOfContainer() {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			if err := r.Skip(); err != nil {
				return err
			}
			continue
		}

		switch tag.TagNumber() {
		case attrPathTagEnableTagCompression:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			p.EnableTagCompression = &v

		case attrPathTagNode:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			nodeID := NodeID(v)
			p.Node = &nodeID

		case attrPathTagEndpoint:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			endpointID := EndpointID(v)
			p.Endpoint = &endpointID

		case attrPathTagCluster:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			clusterID := ClusterID(v)
			p.Cluster = &clusterID

		case attrPathTagAttribute:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			attributeID := AttributeID(v)
			p.Attribute = &attributeID

		case attrPathTagListIndex:
			if r.Type() == tlv.ElementTypeNull {
				p.ListIndex = nil
			} else {
				v, err := r.Uint()
				if err != nil {
					return err
				}
				listIndex := ListIndex(v)
				p.ListIndex = &listIndex
			}

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	return r.ExitContainer()
}
