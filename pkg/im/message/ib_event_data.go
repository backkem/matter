package message

import (
	"bytes"
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// EventDataIB contains event data.
// Spec: Section 10.6.9
// Container type: Structure
type EventDataIB struct {
	Path                 EventPathIB // Tag 0
	EventNumber          EventNumber // Tag 1
	Priority             uint8       // Tag 2
	EpochTimestamp       *uint64     // Tag 3 (optional)
	SystemTimestamp      *uint64     // Tag 4 (optional)
	DeltaEpochTimestamp  *uint64     // Tag 5 (optional)
	DeltaSystemTimestamp *uint64     // Tag 6 (optional)
	Data                 []byte      // Tag 7 (raw TLV)
}

// Context tags for EventDataIB.
const (
	eventDataTagPath                 = 0
	eventDataTagEventNumber          = 1
	eventDataTagPriority             = 2
	eventDataTagEpochTimestamp       = 3
	eventDataTagSystemTimestamp      = 4
	eventDataTagDeltaEpochTimestamp  = 5
	eventDataTagDeltaSystemTimestamp = 6
	eventDataTagData                 = 7
)

// Event priority levels.
const (
	EventPriorityDebug    uint8 = 0
	EventPriorityInfo     uint8 = 1
	EventPriorityCritical uint8 = 2
)

// Encode writes the EventDataIB to the TLV writer.
func (e *EventDataIB) Encode(w *tlv.Writer) error {
	return e.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the EventDataIB with a specific tag.
func (e *EventDataIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if err := e.Path.EncodeWithTag(w, tlv.ContextTag(eventDataTagPath)); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(eventDataTagEventNumber), uint64(e.EventNumber)); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(eventDataTagPriority), uint64(e.Priority)); err != nil {
		return err
	}

	if e.EpochTimestamp != nil {
		if err := w.PutUint(tlv.ContextTag(eventDataTagEpochTimestamp), *e.EpochTimestamp); err != nil {
			return err
		}
	}

	if e.SystemTimestamp != nil {
		if err := w.PutUint(tlv.ContextTag(eventDataTagSystemTimestamp), *e.SystemTimestamp); err != nil {
			return err
		}
	}

	if e.DeltaEpochTimestamp != nil {
		if err := w.PutUint(tlv.ContextTag(eventDataTagDeltaEpochTimestamp), *e.DeltaEpochTimestamp); err != nil {
			return err
		}
	}

	if e.DeltaSystemTimestamp != nil {
		if err := w.PutUint(tlv.ContextTag(eventDataTagDeltaSystemTimestamp), *e.DeltaSystemTimestamp); err != nil {
			return err
		}
	}

	if len(e.Data) > 0 {
		if err := w.PutRaw(tlv.ContextTag(eventDataTagData), e.Data); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads an EventDataIB from the TLV reader.
func (e *EventDataIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return e.DecodeFrom(r)
}

// DecodeFrom reads an EventDataIB assuming the reader is positioned
// at the container start.
func (e *EventDataIB) DecodeFrom(r *tlv.Reader) error {
	if err := r.EnterContainer(); err != nil {
		return err
	}

	var hasPath, hasEventNumber, hasPriority bool

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
		case eventDataTagPath:
			if err := e.Path.DecodeFrom(r); err != nil {
				return err
			}
			hasPath = true

		case eventDataTagEventNumber:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			e.EventNumber = EventNumber(v)
			hasEventNumber = true

		case eventDataTagPriority:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			e.Priority = uint8(v)
			hasPriority = true

		case eventDataTagEpochTimestamp:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			e.EpochTimestamp = &v

		case eventDataTagSystemTimestamp:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			e.SystemTimestamp = &v

		case eventDataTagDeltaEpochTimestamp:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			e.DeltaEpochTimestamp = &v

		case eventDataTagDeltaSystemTimestamp:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			e.DeltaSystemTimestamp = &v

		case eventDataTagData:
			data, err := r.Bytes()
			if err != nil {
				return err
			}
			e.Data = data

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	if err := r.ExitContainer(); err != nil {
		return err
	}

	if !hasPath || !hasEventNumber || !hasPriority {
		return ErrMissingField
	}

	return nil
}

// SetDataValue encodes event data and stores it.
func (e *EventDataIB) SetDataValue(encode func(w *tlv.Writer) error) error {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := encode(w); err != nil {
		return err
	}
	e.Data = buf.Bytes()
	return nil
}
