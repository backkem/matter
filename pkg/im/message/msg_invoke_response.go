package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// InvokeResponseMessage contains results of command invocations.
// Spec: Section 10.7.10
// Opcode: 0x09
// Container type: Structure
type InvokeResponseMessage struct {
	SuppressResponse    bool               // Tag 0
	InvokeResponses     []InvokeResponseIB // Tag 1
	MoreChunkedMessages bool               // Tag 2
}

// Context tags for InvokeResponseMessage.
const (
	invokeRespMsgTagSuppressResponse    = 0
	invokeRespMsgTagInvokeResponses     = 1
	invokeRespMsgTagMoreChunkedMessages = 2
)

// Encode writes the InvokeResponseMessage to the TLV writer.
func (m *InvokeResponseMessage) Encode(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	if err := w.PutBool(tlv.ContextTag(invokeRespMsgTagSuppressResponse), m.SuppressResponse); err != nil {
		return err
	}

	if err := w.StartArray(tlv.ContextTag(invokeRespMsgTagInvokeResponses)); err != nil {
		return err
	}
	for i := range m.InvokeResponses {
		if err := m.InvokeResponses[i].EncodeWithTag(w, tlv.Anonymous()); err != nil {
			return err
		}
	}
	if err := w.EndContainer(); err != nil {
		return err
	}

	if err := w.PutBool(tlv.ContextTag(invokeRespMsgTagMoreChunkedMessages), m.MoreChunkedMessages); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads an InvokeResponseMessage from the TLV reader.
func (m *InvokeResponseMessage) Decode(r *tlv.Reader) error {
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
		case invokeRespMsgTagSuppressResponse:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			m.SuppressResponse = v

		case invokeRespMsgTagInvokeResponses:
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
				var resp InvokeResponseIB
				if err := resp.DecodeFrom(r); err != nil {
					return err
				}
				m.InvokeResponses = append(m.InvokeResponses, resp)
			}
			if err := r.ExitContainer(); err != nil {
				return err
			}

		case invokeRespMsgTagMoreChunkedMessages:
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
