package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// AttributeStatusIB contains status information for an attribute operation.
// Spec: Section 10.6.15
// Container type: Structure
type AttributeStatusIB struct {
	Path   AttributePathIB // Tag 0
	Status StatusIB        // Tag 1
}

// Context tags for AttributeStatusIB.
const (
	attrStatusTagPath   = 0
	attrStatusTagStatus = 1
)

// Encode writes the AttributeStatusIB to the TLV writer.
func (a *AttributeStatusIB) Encode(w *tlv.Writer) error {
	return a.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the AttributeStatusIB with a specific tag.
func (a *AttributeStatusIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if err := a.Path.EncodeWithTag(w, tlv.ContextTag(attrStatusTagPath)); err != nil {
		return err
	}

	if err := a.Status.EncodeWithTag(w, tlv.ContextTag(attrStatusTagStatus)); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads an AttributeStatusIB from the TLV reader.
func (a *AttributeStatusIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return a.DecodeFrom(r)
}

// DecodeFrom reads an AttributeStatusIB assuming the reader is positioned
// at the container start.
func (a *AttributeStatusIB) DecodeFrom(r *tlv.Reader) error {
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
		case attrStatusTagPath:
			if err := a.Path.DecodeFrom(r); err != nil {
				return err
			}
			hasPath = true

		case attrStatusTagStatus:
			if err := a.Status.DecodeFrom(r); err != nil {
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
