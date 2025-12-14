package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// ReadRequestMessage requests attribute and/or event data.
// Spec: Section 10.7.2
// Opcode: 0x02
// Container type: Structure
type ReadRequestMessage struct {
	AttributeRequests  []AttributePathIB     // Tag 0
	EventRequests      []EventPathIB         // Tag 1
	EventFilters       []EventFilterIB       // Tag 2
	FabricFiltered     bool                  // Tag 3
	DataVersionFilters []DataVersionFilterIB // Tag 4
}

// Context tags for ReadRequestMessage.
const (
	readReqTagAttributeRequests  = 0
	readReqTagEventRequests      = 1
	readReqTagEventFilters       = 2
	readReqTagFabricFiltered     = 3
	readReqTagDataVersionFilters = 4
)

// Encode writes the ReadRequestMessage to the TLV writer.
func (m *ReadRequestMessage) Encode(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	if len(m.AttributeRequests) > 0 {
		if err := w.StartArray(tlv.ContextTag(readReqTagAttributeRequests)); err != nil {
			return err
		}
		for i := range m.AttributeRequests {
			if err := m.AttributeRequests[i].EncodeWithTag(w, tlv.Anonymous()); err != nil {
				return err
			}
		}
		if err := w.EndContainer(); err != nil {
			return err
		}
	}

	if len(m.EventRequests) > 0 {
		if err := w.StartArray(tlv.ContextTag(readReqTagEventRequests)); err != nil {
			return err
		}
		for i := range m.EventRequests {
			if err := m.EventRequests[i].EncodeWithTag(w, tlv.Anonymous()); err != nil {
				return err
			}
		}
		if err := w.EndContainer(); err != nil {
			return err
		}
	}

	if len(m.EventFilters) > 0 {
		if err := w.StartArray(tlv.ContextTag(readReqTagEventFilters)); err != nil {
			return err
		}
		for i := range m.EventFilters {
			if err := m.EventFilters[i].EncodeWithTag(w, tlv.Anonymous()); err != nil {
				return err
			}
		}
		if err := w.EndContainer(); err != nil {
			return err
		}
	}

	if err := w.PutBool(tlv.ContextTag(readReqTagFabricFiltered), m.FabricFiltered); err != nil {
		return err
	}

	if len(m.DataVersionFilters) > 0 {
		if err := w.StartArray(tlv.ContextTag(readReqTagDataVersionFilters)); err != nil {
			return err
		}
		for i := range m.DataVersionFilters {
			if err := m.DataVersionFilters[i].EncodeWithTag(w, tlv.Anonymous()); err != nil {
				return err
			}
		}
		if err := w.EndContainer(); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// Decode reads a ReadRequestMessage from the TLV reader.
func (m *ReadRequestMessage) Decode(r *tlv.Reader) error {
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
		case readReqTagAttributeRequests:
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
				var path AttributePathIB
				if err := path.DecodeFrom(r); err != nil {
					return err
				}
				m.AttributeRequests = append(m.AttributeRequests, path)
			}
			if err := r.ExitContainer(); err != nil {
				return err
			}

		case readReqTagEventRequests:
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
				var path EventPathIB
				if err := path.DecodeFrom(r); err != nil {
					return err
				}
				m.EventRequests = append(m.EventRequests, path)
			}
			if err := r.ExitContainer(); err != nil {
				return err
			}

		case readReqTagEventFilters:
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
				var filter EventFilterIB
				if err := filter.DecodeFrom(r); err != nil {
					return err
				}
				m.EventFilters = append(m.EventFilters, filter)
			}
			if err := r.ExitContainer(); err != nil {
				return err
			}

		case readReqTagFabricFiltered:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			m.FabricFiltered = v

		case readReqTagDataVersionFilters:
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
				var filter DataVersionFilterIB
				if err := filter.DecodeFrom(r); err != nil {
					return err
				}
				m.DataVersionFilters = append(m.DataVersionFilters, filter)
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
