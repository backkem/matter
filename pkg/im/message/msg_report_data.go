package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// ReportDataMessage contains attribute and/or event data.
// Spec: Section 10.7.3
// Opcode: 0x05
// Container type: Structure
type ReportDataMessage struct {
	SubscriptionID      *SubscriptionID     // Tag 0 (optional)
	AttributeReports    []AttributeReportIB // Tag 1
	EventReports        []EventReportIB     // Tag 2
	MoreChunkedMessages bool                // Tag 3
	SuppressResponse    bool                // Tag 4
}

// Context tags for ReportDataMessage.
const (
	reportDataTagSubscriptionID      = 0
	reportDataTagAttributeReports    = 1
	reportDataTagEventReports        = 2
	reportDataTagMoreChunkedMessages = 3
	reportDataTagSuppressResponse    = 4
)

// Encode writes the ReportDataMessage to the TLV writer.
func (m *ReportDataMessage) Encode(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	if m.SubscriptionID != nil {
		if err := w.PutUint(tlv.ContextTag(reportDataTagSubscriptionID), uint64(*m.SubscriptionID)); err != nil {
			return err
		}
	}

	if len(m.AttributeReports) > 0 {
		if err := w.StartArray(tlv.ContextTag(reportDataTagAttributeReports)); err != nil {
			return err
		}
		for i := range m.AttributeReports {
			if err := m.AttributeReports[i].EncodeWithTag(w, tlv.Anonymous()); err != nil {
				return err
			}
		}
		if err := w.EndContainer(); err != nil {
			return err
		}
	}

	if len(m.EventReports) > 0 {
		if err := w.StartArray(tlv.ContextTag(reportDataTagEventReports)); err != nil {
			return err
		}
		for i := range m.EventReports {
			if err := m.EventReports[i].EncodeWithTag(w, tlv.Anonymous()); err != nil {
				return err
			}
		}
		if err := w.EndContainer(); err != nil {
			return err
		}
	}

	if err := w.PutBool(tlv.ContextTag(reportDataTagMoreChunkedMessages), m.MoreChunkedMessages); err != nil {
		return err
	}

	if err := w.PutBool(tlv.ContextTag(reportDataTagSuppressResponse), m.SuppressResponse); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads a ReportDataMessage from the TLV reader.
func (m *ReportDataMessage) Decode(r *tlv.Reader) error {
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
		case reportDataTagSubscriptionID:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			subID := SubscriptionID(v)
			m.SubscriptionID = &subID

		case reportDataTagAttributeReports:
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
				var report AttributeReportIB
				if err := report.DecodeFrom(r); err != nil {
					return err
				}
				m.AttributeReports = append(m.AttributeReports, report)
			}
			if err := r.ExitContainer(); err != nil {
				return err
			}

		case reportDataTagEventReports:
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
				var report EventReportIB
				if err := report.DecodeFrom(r); err != nil {
					return err
				}
				m.EventReports = append(m.EventReports, report)
			}
			if err := r.ExitContainer(); err != nil {
				return err
			}

		case reportDataTagMoreChunkedMessages:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			m.MoreChunkedMessages = v

		case reportDataTagSuppressResponse:
			v, err := r.Bool()
			if err != nil {
				return err
			}
			m.SuppressResponse = v

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	return r.ExitContainer()
}
