package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// CommandPathIB identifies a command.
// Spec: Section 10.6.11
// Container type: List
type CommandPathIB struct {
	Endpoint EndpointID // Tag 0
	Cluster  ClusterID  // Tag 1
	Command  CommandID  // Tag 2
}

// Context tags for CommandPathIB.
const (
	cmdPathTagEndpoint = 0
	cmdPathTagCluster  = 1
	cmdPathTagCommand  = 2
)

// Encode writes the CommandPathIB to the TLV writer.
func (p *CommandPathIB) Encode(w *tlv.Writer) error {
	return p.EncodeWithTag(w, tlv.Anonymous())
}

// EncodeWithTag writes the CommandPathIB with a specific tag.
func (p *CommandPathIB) EncodeWithTag(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartList(tag); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(cmdPathTagEndpoint), uint64(p.Endpoint)); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(cmdPathTagCluster), uint64(p.Cluster)); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(cmdPathTagCommand), uint64(p.Command)); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads a CommandPathIB from the TLV reader.
func (p *CommandPathIB) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeList {
		return ErrInvalidType
	}

	return p.DecodeFrom(r)
}

// DecodeFrom reads a CommandPathIB assuming the reader is positioned
// at the container start.
func (p *CommandPathIB) DecodeFrom(r *tlv.Reader) error {
	if err := r.EnterContainer(); err != nil {
		return err
	}

	var hasEndpoint, hasCluster, hasCommand bool

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
		case cmdPathTagEndpoint:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			p.Endpoint = EndpointID(v)
			hasEndpoint = true

		case cmdPathTagCluster:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			p.Cluster = ClusterID(v)
			hasCluster = true

		case cmdPathTagCommand:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			p.Command = CommandID(v)
			hasCommand = true

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	if err := r.ExitContainer(); err != nil {
		return err
	}

	if !hasEndpoint || !hasCluster || !hasCommand {
		return ErrMissingField
	}

	return nil
}
