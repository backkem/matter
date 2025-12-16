package im

import (
	"testing"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// testEventPayload implements TLVMarshaler for testing.
type testEventPayload struct {
	Value    uint32
	Message  string
	IsActive bool
}

func (p *testEventPayload) MarshalTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}
	if err := w.PutUint(tlv.ContextTag(0), uint64(p.Value)); err != nil {
		return err
	}
	if err := w.PutString(tlv.ContextTag(1), p.Message); err != nil {
		return err
	}
	if err := w.PutBool(tlv.ContextTag(2), p.IsActive); err != nil {
		return err
	}
	return w.EndContainer()
}

// badMarshaler always fails.
type badMarshaler struct{}

func (b *badMarshaler) MarshalTLV(w *tlv.Writer) error {
	// Start a struct but don't end it properly - this won't fail
	// Instead, let's return an error explicitly
	return tlv.ErrInvalidElementType
}

func TestEventManagerPublisher_PublishEvent_NilPayload(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})
	pub := NewEventManagerPublisher(em)

	num, err := pub.PublishEvent(1, 0x0006, 0x00, datamodel.EventPriorityInfo, nil, 0)
	if err != nil {
		t.Fatalf("PublishEvent() error = %v", err)
	}
	if num == 0 {
		t.Error("EventNumber = 0, want non-zero")
	}

	// Verify event was stored
	events := em.GetEvents(nil, nil, 0, nil)
	if len(events) != 1 {
		t.Fatalf("stored events = %d, want 1", len(events))
	}
	if events[0].Data != nil {
		t.Errorf("Data = %v, want nil", events[0].Data)
	}
}

func TestEventManagerPublisher_PublishEvent_ByteSlice(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})
	pub := NewEventManagerPublisher(em)

	rawData := []byte{0x15, 0x24, 0x00, 0x2A, 0x18} // Pre-encoded TLV
	num, err := pub.PublishEvent(1, 0x0006, 0x00, datamodel.EventPriorityInfo, rawData, 0)
	if err != nil {
		t.Fatalf("PublishEvent() error = %v", err)
	}
	if num == 0 {
		t.Error("EventNumber = 0, want non-zero")
	}

	events := em.GetEvents(nil, nil, 0, nil)
	if len(events) != 1 {
		t.Fatalf("stored events = %d, want 1", len(events))
	}

	// Data should be used directly
	if string(events[0].Data) != string(rawData) {
		t.Errorf("Data mismatch")
	}
}

func TestEventManagerPublisher_PublishEvent_TLVMarshaler(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})
	pub := NewEventManagerPublisher(em)

	payload := &testEventPayload{
		Value:    42,
		Message:  "test",
		IsActive: true,
	}

	num, err := pub.PublishEvent(1, 0x0006, 0x00, datamodel.EventPriorityCritical, payload, 0)
	if err != nil {
		t.Fatalf("PublishEvent() error = %v", err)
	}
	if num == 0 {
		t.Error("EventNumber = 0, want non-zero")
	}

	events := em.GetEvents(nil, nil, 0, nil)
	if len(events) != 1 {
		t.Fatalf("stored events = %d, want 1", len(events))
	}

	// Data should be TLV-encoded
	if len(events[0].Data) == 0 {
		t.Error("Data is empty, want encoded TLV")
	}

	// Verify priority mapping
	if events[0].Priority != EventPriorityCritical {
		t.Errorf("Priority = %v, want Critical", events[0].Priority)
	}
}

func TestEventManagerPublisher_PublishEvent_FabricScoped(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})
	pub := NewEventManagerPublisher(em)

	num, err := pub.PublishEvent(2, 0x0028, 0x01, datamodel.EventPriorityInfo, nil, 3)
	if err != nil {
		t.Fatalf("PublishEvent() error = %v", err)
	}
	if num == 0 {
		t.Error("EventNumber = 0, want non-zero")
	}

	events := em.GetEvents(nil, nil, 0, nil)
	if len(events) != 1 {
		t.Fatalf("stored events = %d, want 1", len(events))
	}

	if events[0].FabricIndex != 3 {
		t.Errorf("FabricIndex = %d, want 3", events[0].FabricIndex)
	}
}

func TestEventManagerPublisher_PublishEvent_MarshalError(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})
	pub := NewEventManagerPublisher(em)

	payload := &badMarshaler{}
	_, err := pub.PublishEvent(1, 0x0006, 0x00, datamodel.EventPriorityInfo, payload, 0)

	if err == nil {
		t.Error("PublishEvent() error = nil, want error")
	}
}

func TestEventManagerPublisher_PublishEvent_UnsupportedType(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})
	pub := NewEventManagerPublisher(em)

	// Pass a type that doesn't implement TLVMarshaler
	_, err := pub.PublishEvent(1, 0x0006, 0x00, datamodel.EventPriorityInfo, "unsupported", 0)

	if err == nil {
		t.Error("PublishEvent() error = nil, want error for unsupported type")
	}
}

func TestEventManagerPublisher_PublishEvent_PriorityMapping(t *testing.T) {
	tests := []struct {
		input    datamodel.EventPriority
		expected EventPriority
	}{
		{datamodel.EventPriorityDebug, EventPriorityDebug},
		{datamodel.EventPriorityInfo, EventPriorityInfo},
		{datamodel.EventPriorityCritical, EventPriorityCritical},
	}

	for _, tt := range tests {
		t.Run(tt.input.String(), func(t *testing.T) {
			em := NewEventManager(EventManagerConfig{})
			pub := NewEventManagerPublisher(em)

			_, err := pub.PublishEvent(1, 0x0006, 0x00, tt.input, nil, 0)
			if err != nil {
				t.Fatalf("PublishEvent() error = %v", err)
			}

			events := em.GetEvents(nil, nil, 0, []EventPriority{tt.expected})
			if len(events) != 1 {
				t.Errorf("event not found in %v queue", tt.expected)
			}
		})
	}
}

func TestEventManagerPublisher_Interface(t *testing.T) {
	// Verify the publisher implements datamodel.EventPublisher
	em := NewEventManager(EventManagerConfig{})
	var _ datamodel.EventPublisher = NewEventManagerPublisher(em)
}
