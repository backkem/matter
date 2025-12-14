package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// TimedRequestMessage initiates a timed interaction.
// Spec: Section 10.7.8
// Opcode: 0x0a
// Container type: Structure
type TimedRequestMessage struct {
	Timeout uint16 // Tag 0 (timeout in milliseconds)
}

// Context tags for TimedRequestMessage.
const (
	timedReqTagTimeout = 0
)

// Encode writes the TimedRequestMessage to the TLV writer.
func (m *TimedRequestMessage) Encode(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(timedReqTagTimeout), uint64(m.Timeout)); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads a TimedRequestMessage from the TLV reader.
func (m *TimedRequestMessage) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	if err := r.EnterContainer(); err != nil {
		return err
	}

	var hasTimeout bool

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
		case timedReqTagTimeout:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			m.Timeout = uint16(v)
			hasTimeout = true

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	if err := r.ExitContainer(); err != nil {
		return err
	}

	if !hasTimeout {
		return ErrMissingField
	}

	return nil
}
