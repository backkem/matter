package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// StatusResponseMessage is a response containing only a status code.
// Spec: Section 10.7.1
// Opcode: 0x01
// Container type: Structure
type StatusResponseMessage struct {
	Status Status // Tag 0
}

// Context tags for StatusResponseMessage.
const (
	statusRespTagStatus = 0
)

// Encode writes the StatusResponseMessage to the TLV writer.
func (m *StatusResponseMessage) Encode(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(statusRespTagStatus), uint64(m.Status)); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads a StatusResponseMessage from the TLV reader.
func (m *StatusResponseMessage) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	if err := r.EnterContainer(); err != nil {
		return err
	}

	var hasStatus bool

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
		case statusRespTagStatus:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			m.Status = Status(v)
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

	if !hasStatus {
		return ErrMissingField
	}

	return nil
}
