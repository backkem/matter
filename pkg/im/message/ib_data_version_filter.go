package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// DataVersionFilterIB filters attributes by cluster path and data version.
// Spec: Section 10.6.5
// Container type: Structure
type DataVersionFilterIB struct {
	Path        ClusterPathIB // Tag 0
	DataVersion DataVersion   // Tag 1
}

// Context tags for DataVersionFilterIB.
const (
	dataVersionFilterTagPath        = 0
	dataVersionFilterTagDataVersion = 1
)

// Encode writes the DataVersionFilterIB to the TLV writer.
func (f *DataVersionFilterIB) Encode(w *tlv.Writer) error {
	return f.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the DataVersionFilterIB with a specific tag.
func (f *DataVersionFilterIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if err := f.Path.EncodeWithTag(w, tlv.ContextTag(dataVersionFilterTagPath)); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(dataVersionFilterTagDataVersion), uint64(f.DataVersion)); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads a DataVersionFilterIB from the TLV reader.
func (f *DataVersionFilterIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return f.DecodeFrom(r)
}

// DecodeFrom reads a DataVersionFilterIB assuming the reader is positioned
// at the container start.
func (f *DataVersionFilterIB) DecodeFrom(r *tlv.Reader) error {
	if err := r.EnterContainer(); err != nil {
		return err
	}

	var hasPath, hasDataVersion bool

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
		case dataVersionFilterTagPath:
			if err := f.Path.DecodeFrom(r); err != nil {
				return err
			}
			hasPath = true

		case dataVersionFilterTagDataVersion:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			f.DataVersion = DataVersion(v)
			hasDataVersion = true

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	if err := r.ExitContainer(); err != nil {
		return err
	}

	if !hasPath || !hasDataVersion {
		return ErrMissingField
	}

	return nil
}
