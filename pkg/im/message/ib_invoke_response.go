package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// InvokeResponseIB contains either command response data or a status.
// Spec: Section 10.6.14
// Container type: Structure
type InvokeResponseIB struct {
	Command *CommandDataIB   // Tag 0
	Status  *CommandStatusIB // Tag 1
}

// Context tags for InvokeResponseIB.
const (
	invokeRespTagCommand = 0
	invokeRespTagStatus  = 1
)

// Encode writes the InvokeResponseIB to the TLV writer.
func (i *InvokeResponseIB) Encode(w *tlv.Writer) error {
	return i.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the InvokeResponseIB with a specific tag.
func (i *InvokeResponseIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if i.Command != nil {
		if err := i.Command.EncodeWithTag(w, tlv.ContextTag(invokeRespTagCommand)); err != nil {
			return err
		}
	}

	if i.Status != nil {
		if err := i.Status.EncodeWithTag(w, tlv.ContextTag(invokeRespTagStatus)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads an InvokeResponseIB from the TLV reader.
func (i *InvokeResponseIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return i.DecodeFrom(r)
}

// DecodeFrom reads an InvokeResponseIB assuming the reader is positioned
// at the container start.
func (i *InvokeResponseIB) DecodeFrom(r *tlv.Reader) error {
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
		case invokeRespTagCommand:
			i.Command = &CommandDataIB{}
			if err := i.Command.DecodeFrom(r); err != nil {
				return err
			}

		case invokeRespTagStatus:
			i.Status = &CommandStatusIB{}
			if err := i.Status.DecodeFrom(r); err != nil {
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

// IsCommand returns true if this response contains command data.
func (i *InvokeResponseIB) IsCommand() bool {
	return i.Command != nil
}

// IsStatus returns true if this response contains a status (error).
func (i *InvokeResponseIB) IsStatus() bool {
	return i.Status != nil
}
