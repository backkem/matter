package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// WriteResponseMessage contains results of a write operation.
// Spec: Section 10.7.7
// Opcode: 0x07
// Container type: Structure
type WriteResponseMessage struct {
	WriteResponses []AttributeStatusIB // Tag 0
}

// Context tags for WriteResponseMessage.
const (
	writeRespTagWriteResponses = 0
)

// Encode writes the WriteResponseMessage to the TLV writer.
func (m *WriteResponseMessage) Encode(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	if err := w.StartArray(tlv.ContextTag(writeRespTagWriteResponses)); err != nil {
		return err
	}
	for i := range m.WriteResponses {
		if err := m.WriteResponses[i].EncodeWithTag(w, tlv.Anonymous()); err != nil {
			return err
		}
	}
	if err := w.EndContainer(); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads a WriteResponseMessage from the TLV reader.
func (m *WriteResponseMessage) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
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
		case writeRespTagWriteResponses:
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
				var status AttributeStatusIB
				if err := status.DecodeFrom(r); err != nil {
					return err
				}
				m.WriteResponses = append(m.WriteResponses, status)
			}
			if err := r.ExitContainer(); err != nil {
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
