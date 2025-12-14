package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// WriteRequestMessage requests writing attribute values.
// Spec: Section 10.7.6
// Opcode: 0x06
// Container type: Structure
type WriteRequestMessage struct {
	SuppressResponse    bool              // Tag 0
	TimedRequest        bool              // Tag 1
	WriteRequests       []AttributeDataIB // Tag 2
	MoreChunkedMessages bool              // Tag 3
}

// Context tags for WriteRequestMessage.
const (
	writeReqTagSuppressResponse    = 0
	writeReqTagTimedRequest        = 1
	writeReqTagWriteRequests       = 2
	writeReqTagMoreChunkedMessages = 3
)

// Encode writes the WriteRequestMessage to the TLV writer.
func (m *WriteRequestMessage) Encode(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	if err := w.PutBool(tlv.ContextTag(writeReqTagSuppressResponse), m.SuppressResponse); err != nil {
		return err
	}

	if err := w.PutBool(tlv.ContextTag(writeReqTagTimedRequest), m.TimedRequest); err != nil {
		return err
	}

	if len(m.WriteRequests) > 0 {
		if err := w.StartArray(tlv.ContextTag(writeReqTagWriteRequests)); err != nil {
			return err
		}
		for i := range m.WriteRequests {
			if err := m.WriteRequests[i].EncodeWithTag(w, tlv.Anonymous()); err != nil {
				return err
			}
		}
		if err := w.EndContainer(); err != nil {
			return err
		}
	}

	if err := w.PutBool(tlv.ContextTag(writeReqTagMoreChunkedMessages), m.MoreChunkedMessages); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads a WriteRequestMessage from the TLV reader.
func (m *WriteRequestMessage) Decode(r *tlv.Reader) error {
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
		case writeReqTagSuppressResponse:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			m.SuppressResponse = v

		case writeReqTagTimedRequest:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			m.TimedRequest = v

		case writeReqTagWriteRequests:
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
				var data AttributeDataIB
				if err := data.DecodeFrom(r); err != nil {
					return err
				}
				m.WriteRequests = append(m.WriteRequests, data)
			}
			if err := r.ExitContainer(); err != nil {
				return err
			}

		case writeReqTagMoreChunkedMessages:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			m.MoreChunkedMessages = v

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	return r.ExitContainer()
}
