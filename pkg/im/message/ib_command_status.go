package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// CommandStatusIB contains status information for a command invocation.
// Spec: Section 10.6.13
// Container type: Structure
type CommandStatusIB struct {
	Path   CommandPathIB // Tag 0
	Status StatusIB      // Tag 1
	Ref    *uint16       // Tag 2 (optional, for batch commands)
}

// Context tags for CommandStatusIB.
const (
	cmdStatusTagPath   = 0
	cmdStatusTagStatus = 1
	cmdStatusTagRef    = 2
)

// Encode writes the CommandStatusIB to the TLV writer.
func (c *CommandStatusIB) Encode(w *tlv.Writer) error {
	return c.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the CommandStatusIB with a specific tag.
func (c *CommandStatusIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if err := c.Path.EncodeWithTag(w, tlv.ContextTag(cmdStatusTagPath)); err != nil {
		return err
	}

	if err := c.Status.EncodeWithTag(w, tlv.ContextTag(cmdStatusTagStatus)); err != nil {
		return err
	}

	if c.Ref != nil {
		if err := w.PutUint(tlv.ContextTag(cmdStatusTagRef), uint64(*c.Ref)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads a CommandStatusIB from the TLV reader.
func (c *CommandStatusIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return c.DecodeFrom(r)
}

// DecodeFrom reads a CommandStatusIB assuming the reader is positioned
// at the container start.
func (c *CommandStatusIB) DecodeFrom(r *tlv.Reader) error {
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
		case cmdStatusTagPath:
			if err := c.Path.DecodeFrom(r); err != nil {
				return err
			}
			hasPath = true

		case cmdStatusTagStatus:
			if err := c.Status.DecodeFrom(r); err != nil {
				return err
			}
			hasStatus = true

		case cmdStatusTagRef:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			ref := uint16(v)
			c.Ref = &ref

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
