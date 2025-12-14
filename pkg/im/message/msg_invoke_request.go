package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// InvokeRequestMessage requests command invocation.
// Spec: Section 10.7.9
// Opcode: 0x08
// Container type: Structure
type InvokeRequestMessage struct {
	SuppressResponse bool            // Tag 0
	TimedRequest     bool            // Tag 1
	InvokeRequests   []CommandDataIB // Tag 2
}

// Context tags for InvokeRequestMessage.
const (
	invokeReqTagSuppressResponse = 0
	invokeReqTagTimedRequest     = 1
	invokeReqTagInvokeRequests   = 2
)

// Encode writes the InvokeRequestMessage to the TLV writer.
func (m *InvokeRequestMessage) Encode(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	if err := w.PutBool(tlv.ContextTag(invokeReqTagSuppressResponse), m.SuppressResponse); err != nil {
		return err
	}

	if err := w.PutBool(tlv.ContextTag(invokeReqTagTimedRequest), m.TimedRequest); err != nil {
		return err
	}

	if err := w.StartArray(tlv.ContextTag(invokeReqTagInvokeRequests)); err != nil {
		return err
	}
	for i := range m.InvokeRequests {
		if err := m.InvokeRequests[i].EncodeWithTag(w, tlv.Anonymous()); err != nil {
			return err
		}
	}
	if err := w.EndContainer(); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads an InvokeRequestMessage from the TLV reader.
func (m *InvokeRequestMessage) Decode(r *tlv.Reader) error {
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
		case invokeReqTagSuppressResponse:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			m.SuppressResponse = v

		case invokeReqTagTimedRequest:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			m.TimedRequest = v

		case invokeReqTagInvokeRequests:
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
				var cmd CommandDataIB
				if err := cmd.DecodeFrom(r); err != nil {
					return err
				}
				m.InvokeRequests = append(m.InvokeRequests, cmd)
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
