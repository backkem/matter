package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// ClusterPathIB identifies a cluster.
// Spec: Section 10.6.3
// Container type: List
type ClusterPathIB struct {
	Node     *NodeID     // Tag 0
	Endpoint *EndpointID // Tag 1
	Cluster  *ClusterID  // Tag 2
}

// Context tags for ClusterPathIB.
const (
	clusterPathTagNode     = 0
	clusterPathTagEndpoint = 1
	clusterPathTagCluster  = 2
)

// Encode writes the ClusterPathIB to the TLV writer.
func (p *ClusterPathIB) Encode(w *tlv.Writer) error {
	return p.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the ClusterPathIB with a specific tag.
func (p *ClusterPathIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartList(tag); err != nil {
		return err
	}

	if p.Node != nil {
		if err := w.PutUint(tlv.ContextTag(clusterPathTagNode), uint64(*p.Node)); err != nil {
			return err
		}
	}

	if p.Endpoint != nil {
		if err := w.PutUint(tlv.ContextTag(clusterPathTagEndpoint), uint64(*p.Endpoint)); err != nil {
			return err
		}
	}

	if p.Cluster != nil {
		if err := w.PutUint(tlv.ContextTag(clusterPathTagCluster), uint64(*p.Cluster)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads a ClusterPathIB from the TLV reader.
func (p *ClusterPathIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeList {
		return ErrInvalidType
	}

	return p.DecodeFrom(r)
}

// DecodeFrom reads a ClusterPathIB assuming the reader is positioned
// at the container start.
func (p *ClusterPathIB) DecodeFrom(r *tlv.Reader) error {
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
		case clusterPathTagNode:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			nodeID := NodeID(v)
			p.Node = &nodeID

		case clusterPathTagEndpoint:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			endpointID := EndpointID(v)
			p.Endpoint = &endpointID

		case clusterPathTagCluster:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			clusterID := ClusterID(v)
			p.Cluster = &clusterID

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	return r.ExitContainer()
}
