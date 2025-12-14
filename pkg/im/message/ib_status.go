package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// StatusIB contains status information for an action.
// Spec: Section 10.6.17
// Container type: Structure
type StatusIB struct {
	Status        Status // Tag 0 - IM status code
	ClusterStatus *uint8 // Tag 1 - Cluster-specific status (optional)
}

// Context tags for StatusIB.
const (
	statusTagStatus        = 0
	statusTagClusterStatus = 1
)

// Encode writes the StatusIB to the TLV writer.
func (s *StatusIB) Encode(w *tlv.Writer) error {
	return s.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the StatusIB with a specific tag.
func (s *StatusIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(statusTagStatus), uint64(s.Status)); err != nil {
		return err
	}

	if s.ClusterStatus != nil {
		if err := w.PutUint(tlv.ContextTag(statusTagClusterStatus), uint64(*s.ClusterStatus)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads a StatusIB from the TLV reader.
func (s *StatusIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return s.DecodeFrom(r)
}

// DecodeFrom reads a StatusIB assuming the reader is positioned
// at the container start.
func (s *StatusIB) DecodeFrom(r *tlv.Reader) error {
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
		case statusTagStatus:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			s.Status = Status(v)
			hasStatus = true

		case statusTagClusterStatus:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			cs := uint8(v)
			s.ClusterStatus = &cs

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
