package im

import (
	"bytes"
	"fmt"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/tlv"
)

// TLVMarshaler is implemented by types that can marshal themselves to TLV.
// Event payload structs should implement this interface.
type TLVMarshaler interface {
	MarshalTLV(w *tlv.Writer) error
}

// EventManagerPublisher adapts EventManager to implement datamodel.EventPublisher.
// It handles TLV encoding of event payloads centrally.
//
// Payload types should implement TLVMarshaler. If the payload is nil,
// an empty event data is used. If the payload is already []byte, it's
// used directly (for backwards compatibility).
type EventManagerPublisher struct {
	em *EventManager
}

// NewEventManagerPublisher creates a new EventManagerPublisher.
func NewEventManagerPublisher(em *EventManager) *EventManagerPublisher {
	return &EventManagerPublisher{em: em}
}

// PublishEvent implements datamodel.EventPublisher.
// The data parameter can be:
//   - nil: empty event data
//   - TLVMarshaler: will be encoded via MarshalTLV
//   - []byte: used directly (backwards compatibility)
func (p *EventManagerPublisher) PublishEvent(
	endpoint datamodel.EndpointID,
	cluster datamodel.ClusterID,
	eventID datamodel.EventID,
	priority datamodel.EventPriority,
	data interface{},
	fabricIndex uint8,
) (datamodel.EventNumber, error) {
	// Encode the payload
	encoded, err := p.encodePayload(data)
	if err != nil {
		return 0, fmt.Errorf("failed to encode event payload: %w", err)
	}

	// Map priority
	var imPriority EventPriority
	switch priority {
	case datamodel.EventPriorityDebug:
		imPriority = EventPriorityDebug
	case datamodel.EventPriorityInfo:
		imPriority = EventPriorityInfo
	case datamodel.EventPriorityCritical:
		imPriority = EventPriorityCritical
	default:
		imPriority = EventPriorityInfo
	}

	// Publish to EventManager
	eventNum := p.em.PublishEventWithFabric(
		message.EndpointID(endpoint),
		message.ClusterID(cluster),
		message.EventID(eventID),
		imPriority,
		encoded,
		fabricIndex,
	)

	return datamodel.EventNumber(eventNum), nil
}

// encodePayload encodes the event payload to TLV bytes.
func (p *EventManagerPublisher) encodePayload(data interface{}) ([]byte, error) {
	if data == nil {
		return nil, nil
	}

	// If already bytes, use directly (backwards compatibility)
	if b, ok := data.([]byte); ok {
		return b, nil
	}

	// If implements TLVMarshaler, encode via interface
	if m, ok := data.(TLVMarshaler); ok {
		var buf bytes.Buffer
		w := tlv.NewWriter(&buf)
		if err := m.MarshalTLV(w); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	return nil, fmt.Errorf("payload type %T does not implement TLVMarshaler", data)
}

// Verify EventManagerPublisher implements datamodel.EventPublisher.
var _ datamodel.EventPublisher = (*EventManagerPublisher)(nil)
