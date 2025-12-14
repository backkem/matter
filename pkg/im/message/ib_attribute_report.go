package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// AttributeReportIB contains either attribute data or a status.
// Spec: Section 10.6.3
// Container type: Structure
type AttributeReportIB struct {
	AttributeStatus *AttributeStatusIB // Tag 0
	AttributeData   *AttributeDataIB   // Tag 1
}

// Context tags for AttributeReportIB.
const (
	attrReportTagAttributeStatus = 0
	attrReportTagAttributeData   = 1
)

// Encode writes the AttributeReportIB to the TLV writer.
func (a *AttributeReportIB) Encode(w *tlv.Writer) error {
	return a.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the AttributeReportIB with a specific tag.
func (a *AttributeReportIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if a.AttributeStatus != nil {
		if err := a.AttributeStatus.EncodeWithTag(w, tlv.ContextTag(attrReportTagAttributeStatus)); err != nil {
			return err
		}
	}

	if a.AttributeData != nil {
		if err := a.AttributeData.EncodeWithTag(w, tlv.ContextTag(attrReportTagAttributeData)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads an AttributeReportIB from the TLV reader.
func (a *AttributeReportIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return a.DecodeFrom(r)
}

// DecodeFrom reads an AttributeReportIB assuming the reader is positioned
// at the container start.
func (a *AttributeReportIB) DecodeFrom(r *tlv.Reader) error {
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
		case attrReportTagAttributeStatus:
			a.AttributeStatus = &AttributeStatusIB{}
			if err := a.AttributeStatus.DecodeFrom(r); err != nil {
				return err
			}

		case attrReportTagAttributeData:
			a.AttributeData = &AttributeDataIB{}
			if err := a.AttributeData.DecodeFrom(r); err != nil {
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
func (a *AttributeReportIB) IsStatus() bool {
	return a.AttributeStatus != nil
}

// IsData returns true if this report contains attribute data.
func (a *AttributeReportIB) IsData() bool {
	return a.AttributeData != nil
}
