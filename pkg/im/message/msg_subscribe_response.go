package message

import (
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// SubscribeResponseMessage confirms a subscription.
// Spec: Section 10.7.5
// Opcode: 0x04
// Container type: Structure
type SubscribeResponseMessage struct {
	SubscriptionID SubscriptionID // Tag 0
	MaxInterval    uint16         // Tag 2 (note: tag 1 is skipped/reserved)
}

// Context tags for SubscribeResponseMessage.
const (
	subRespTagSubscriptionID = 0
	subRespTagMaxInterval    = 2 // Tag 1 is skipped/reserved
)

// Encode writes the SubscribeResponseMessage to the TLV writer.
func (m *SubscribeResponseMessage) Encode(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(subRespTagSubscriptionID), uint64(m.SubscriptionID)); err != nil {
		return err
	}

	if err := w.PutUint(tlv.ContextTag(subRespTagMaxInterval), uint64(m.MaxInterval)); err != nil {
		return err
	}

	return w.EndContainer()
}

// Decode reads a SubscribeResponseMessage from the TLV reader.
func (m *SubscribeResponseMessage) Decode(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return ErrInvalidType
	}

	if err := r.EnterContainer(); err != nil {
		return err
	}

	var hasSubscriptionID, hasMaxInterval bool

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
		case subRespTagSubscriptionID:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			m.SubscriptionID = SubscriptionID(v)
			hasSubscriptionID = true

		case subRespTagMaxInterval:
			v, err := r.Uint()
			if err != nil {
				return err
			}
			m.MaxInterval = uint16(v)
			hasMaxInterval = true

		default:
			if err := r.Skip(); err != nil {
				return err
			}
		}
	}

	if err := r.ExitContainer(); err != nil {
		return err
	}

	if !hasSubscriptionID || !hasMaxInterval {
		return ErrMissingField
	}

	return nil
}
