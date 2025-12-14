package message

import (
	"bytes"
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// CommandDataIB contains command invocation data.
// Spec: Section 10.6.12
// Container type: Structure
type CommandDataIB struct {
	Path   CommandPathIB // Tag 0
	Fields []byte        // Tag 1 (raw TLV structure)
	Ref    *uint16       // Tag 2 (optional, for batch commands)
}

// Context tags for CommandDataIB.
const (
	cmdDataTagPath   = 0
	cmdDataTagFields = 1
	cmdDataTagRef    = 2
)

// Encode writes the CommandDataIB to the TLV writer.
func (c *CommandDataIB) Encode(w *tlv.Writer) error {
	return c.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the CommandDataIB with a specific tag.
func (c *CommandDataIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartStructure(tag); err != nil {
		return err
	}

	if err := c.Path.EncodeWithTag(w, tlv.ContextTag(cmdDataTagPath)); err != nil {
		return err
	}

	// Fields is written as raw TLV with context tag 1
	if len(c.Fields) > 0 {
		if err := w.PutBytes(tlv.ContextTag(cmdDataTagFields), c.Fields); err != nil {
			return err
		}
	}

	if c.Ref != nil {
		if err := w.PutUint(tlv.ContextTag(cmdDataTagRef), uint64(*c.Ref)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads a CommandDataIB from the TLV reader.
func (c *CommandDataIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	return c.DecodeFrom(r)
}

// DecodeFrom reads a CommandDataIB assuming the reader is positioned
// at the container start.
func (c *CommandDataIB) DecodeFrom(r *tlv.Reader) error {
	if err := r.EnterContainer(); err != nil {
		return err
	}

	var hasPath bool

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
		case cmdDataTagPath:
			if err := c.Path.DecodeFrom(r); err != nil {
				return err
			}
			hasPath = true

		case cmdDataTagFields:
			data, err := r.Bytes()
			if err != nil {
				return err
			}
			c.Fields = data

		case cmdDataTagRef:
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

	if !hasPath {
		return ErrMissingField
	}

	return nil
}

// SetFields encodes command fields and stores them.
func (c *CommandDataIB) SetFields(encode func(w *tlv.Writer) error) error {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := encode(w); err != nil {
		return err
	}
	c.Fields = buf.Bytes()
	return nil
}
