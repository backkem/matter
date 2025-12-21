package message

import (
	"bytes"
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// AttributeDataIB contains attribute data.
// Spec: Section 10.6.4
// Container type: Structure
type AttributeDataIB struct {
	DataVersion DataVersion     // Tag 0
	Path        AttributePathIB // Tag 1
	Data        []byte          // Tag 2 (raw TLV)
}

// Context tags for AttributeDataIB.
const (
	attrDataTagDataVersion = 0
	attrDataTagPath        = 1
	attrDataTagData        = 2
)

// Encode writes the AttributeDataIB to the TLV writer.
func (a *AttributeDataIB) Encode(w *tlv.Writer) error {
	return a.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the AttributeDataIB with a specific tag.
func (a *AttributeDataIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(attrDataTagDataVersion), uint64(a.DataVersion)); err != nil {
		return err
	}

	if err := a.Path.EncodeWithTag(w, tlv.ContextTag(attrDataTagPath)); err != nil {
		return err
	}

	// Data is written as raw TLV with context tag 2
	// The caller is responsible for ensuring Data is valid TLV
	if len(a.Data) > 0 {
		if err := w.PutRaw(tlv.ContextTag(attrDataTagData), a.Data); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads an AttributeDataIB from the TLV reader.
func (a *AttributeDataIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return a.DecodeFrom(r)
}

// DecodeFrom reads an AttributeDataIB assuming the reader is positioned
// at the container start.
func (a *AttributeDataIB) DecodeFrom(r *tlv.Reader) error {
	if err := r.EnterContainer(); err != nil {
		return err
	}

	var hasDataVersion, hasPath bool

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
		case attrDataTagDataVersion:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			a.DataVersion = DataVersion(v)
			hasDataVersion = true

		case attrDataTagPath:
			if err := a.Path.DecodeFrom(r); err != nil {
				return err
			}
			hasPath = true

		case attrDataTagData:
			// Read the raw TLV data
			data, err := r.Bytes()
			if err != nil {
				return err
			}
			a.Data = data

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	if err := r.ExitContainer(); err != nil {
		return err
	}

	if !hasDataVersion || !hasPath {
		return ErrMissingField
	}

	return nil
}

// SetDataValue encodes a value and stores it as the Data field.
// This is a convenience method for setting structured data.
func (a *AttributeDataIB) SetDataValue(encode func(w *tlv.Writer) error) error {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := encode(w); err != nil {
		return err
	}
	a.Data = buf.Bytes()
	return nil
}
