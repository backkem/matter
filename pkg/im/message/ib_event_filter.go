package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// EventFilterIB filters events by node and minimum event number.
// Spec: Section 10.6.6
// Container type: Structure
type EventFilterIB struct {
	Node     *NodeID     // Tag 0 (optional)
	EventMin EventNumber // Tag 1
}

// Context tags for EventFilterIB.
const (
	eventFilterTagNode     = 0
	eventFilterTagEventMin = 1
)

// Encode writes the EventFilterIB to the TLV writer.
func (f *EventFilterIB) Encode(w *tlv.Writer) error {
	return f.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the EventFilterIB with a specific tag.
func (f *EventFilterIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if f.Node != nil {
		if err := w.PutUint(tlv.ContextTag(eventFilterTagNode), uint64(*f.Node)); err != nil {
			return err
		}
	}

	if err := w.PutUint(tlv.ContextTag(eventFilterTagEventMin), uint64(f.EventMin)); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads an EventFilterIB from the TLV reader.
func (f *EventFilterIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return f.DecodeFrom(r)
}

// DecodeFrom reads an EventFilterIB assuming the reader is positioned
// at the container start.
func (f *EventFilterIB) DecodeFrom(r *tlv.Reader) error {
	if err := r.EnterContainer(); err != nil {
		return err
	}

	var hasEventMin bool

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
		case eventFilterTagNode:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			nodeID := NodeID(v)
			f.Node = &nodeID

		case eventFilterTagEventMin:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			f.EventMin = EventNumber(v)
			hasEventMin = true

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	if err := r.ExitContainer(); err != nil {
		return err
	}

	if !hasEventMin {
		return ErrMissingField
	}

	return nil
}
