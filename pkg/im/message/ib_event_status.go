package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// EventStatusIB contains status information for an event.
// Spec: Section 10.6.10
// Container type: Structure
type EventStatusIB struct {
	Path   EventPathIB // Tag 0
	Status StatusIB    // Tag 1
}

// Context tags for EventStatusIB.
const (
	eventStatusTagPath   = 0
	eventStatusTagStatus = 1
)

// Encode writes the EventStatusIB to the TLV writer.
func (e *EventStatusIB) Encode(w *tlv.Writer) error {
	return e.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the EventStatusIB with a specific tag.
func (e *EventStatusIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if err := e.Path.EncodeWithTag(w, tlv.ContextTag(eventStatusTagPath)); err != nil {
		return err
	}

	if err := e.Status.EncodeWithTag(w, tlv.ContextTag(eventStatusTagStatus)); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads an EventStatusIB from the TLV reader.
func (e *EventStatusIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return e.DecodeFrom(r)
}

// DecodeFrom reads an EventStatusIB assuming the reader is positioned
// at the container start.
func (e *EventStatusIB) DecodeFrom(r *tlv.Reader) error {
	if err := r.EnterContainer(); err != nil {
		return err
	}

	var hasPath, hasStatus bool

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
		case eventStatusTagPath:
			if err := e.Path.DecodeFrom(r); err != nil {
				return err
			}
			hasPath = true

		case eventStatusTagStatus:
			if err := e.Status.DecodeFrom(r); err != nil {
				return err
			}
			hasStatus = true

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	if err := r.ExitContainer(); err != nil {
		return err
	}

	if !hasPath || !hasStatus {
		return ErrMissingField
	}

	return nil
}
