package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// EventReportIB contains either event data or a status.
// Spec: Section 10.6.7
// Container type: Structure
type EventReportIB struct {
	EventStatus *EventStatusIB // Tag 0
	EventData   *EventDataIB   // Tag 1
}

// Context tags for EventReportIB.
const (
	eventReportTagEventStatus = 0
	eventReportTagEventData   = 1
)

// Encode writes the EventReportIB to the TLV writer.
func (e *EventReportIB) Encode(w *tlv.Writer) error {
	return e.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the EventReportIB with a specific tag.
func (e *EventReportIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if e.EventStatus != nil {
		if err := e.EventStatus.EncodeWithTag(w, tlv.ContextTag(eventReportTagEventStatus)); err != nil {
			return err
		}
	}

	if e.EventData != nil {
		if err := e.EventData.EncodeWithTag(w, tlv.ContextTag(eventReportTagEventData)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads an EventReportIB from the TLV reader.
func (e *EventReportIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return e.DecodeFrom(r)
}

// DecodeFrom reads an EventReportIB assuming the reader is positioned
// at the container start.
func (e *EventReportIB) DecodeFrom(r *tlv.Reader) error {
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
		case eventReportTagEventStatus:
			e.EventStatus = &EventStatusIB{}
			if err := e.EventStatus.DecodeFrom(r); err != nil {
				return err
			}

		case eventReportTagEventData:
			e.EventData = &EventDataIB{}
			if err := e.EventData.DecodeFrom(r); err != nil {
				return err
			}

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	return r.ExitContainer()
}

// IsStatus returns true if this report contains a status (error).
func (e *EventReportIB) IsStatus() bool {
	return e.EventStatus != nil
}

// IsData returns true if this report contains event data.
func (e *EventReportIB) IsData() bool {
	return e.EventData != nil
}
