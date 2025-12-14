package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// EventPathIB identifies an event or set of events.
// Spec: Section 10.6.8
// Container type: List
type EventPathIB struct {
	Node     *NodeID     // Tag 0
	Endpoint *EndpointID // Tag 1
	Cluster  *ClusterID  // Tag 2
	Event    *EventID    // Tag 3
	IsUrgent *bool       // Tag 4
}

// Context tags for EventPathIB.
const (
	eventPathTagNode     = 0
	eventPathTagEndpoint = 1
	eventPathTagCluster  = 2
	eventPathTagEvent    = 3
	eventPathTagIsUrgent = 4
)

// Encode writes the EventPathIB to the TLV writer.
func (p *EventPathIB) Encode(w *tlv.Writer) error {
	return p.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the EventPathIB with a specific tag.
func (p *EventPathIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartList(tag); err != nil {
		return err
	}

	if p.Node != nil {
		if err := w.PutUint(tlv.ContextTag(eventPathTagNode), uint64(*p.Node)); err != nil {
			return err
		}
	}

	if p.Endpoint != nil {
		if err := w.PutUint(tlv.ContextTag(eventPathTagEndpoint), uint64(*p.Endpoint)); err != nil {
			return err
		}
	}

	if p.Cluster != nil {
		if err := w.PutUint(tlv.ContextTag(eventPathTagCluster), uint64(*p.Cluster)); err != nil {
			return err
		}
	}

	if p.Event != nil {
		if err := w.PutUint(tlv.ContextTag(eventPathTagEvent), uint64(*p.Event)); err != nil {
			return err
		}
	}

	if p.IsUrgent != nil {
		if err := w.PutBool(tlv.ContextTag(eventPathTagIsUrgent), *p.IsUrgent); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads an EventPathIB from the TLV reader.
func (p *EventPathIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeList {
		return ErrInvalidType
	}

	return p.DecodeFrom(r)
}

// DecodeFrom reads an EventPathIB assuming the reader is positioned
// at the container start.
func (p *EventPathIB) DecodeFrom(r *tlv.Reader) error {
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
		case eventPathTagNode:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			nodeID := NodeID(v)
			p.Node = &nodeID

		case eventPathTagEndpoint:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			endpointID := EndpointID(v)
			p.Endpoint = &endpointID

		case eventPathTagCluster:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			clusterID := ClusterID(v)
			p.Cluster = &clusterID

		case eventPathTagEvent:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			eventID := EventID(v)
			p.Event = &eventID

		case eventPathTagIsUrgent:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			p.IsUrgent = &v

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	return r.ExitContainer()
}
