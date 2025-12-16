package datamodel

import (
	"errors"
	"testing"
)

// mockEventPublisher implements EventPublisher for testing.
type mockEventPublisher struct {
	published []publishedEvent
	err       error
	nextNum   EventNumber
}

type publishedEvent struct {
	endpoint    EndpointID
	cluster     ClusterID
	eventID     EventID
	priority    EventPriority
	data        interface{}
	fabricIndex uint8
}

func (m *mockEventPublisher) PublishEvent(
	endpoint EndpointID,
	cluster ClusterID,
	eventID EventID,
	priority EventPriority,
	data interface{},
	fabricIndex uint8,
) (EventNumber, error) {
	if m.err != nil {
		return 0, m.err
	}

	m.published = append(m.published, publishedEvent{
		endpoint:    endpoint,
		cluster:     cluster,
		eventID:     eventID,
		priority:    priority,
		data:        data,
		fabricIndex: fabricIndex,
	})

	m.nextNum++
	return m.nextNum, nil
}

func TestEventSource_NewEventSource(t *testing.T) {
	es := NewEventSource()
	if es == nil {
		t.Fatal("NewEventSource returned nil")
	}
	if es.validEvents == nil {
		t.Error("validEvents map not initialized")
	}
	if es.IsBound() {
		t.Error("new EventSource should not be bound")
	}
}

func TestEventSource_Bind(t *testing.T) {
	es := NewEventSource()
	pub := &mockEventPublisher{}

	es.Bind(1, 0x0006, pub)

	if !es.IsBound() {
		t.Error("EventSource should be bound after Bind()")
	}
	if es.endpoint != 1 {
		t.Errorf("endpoint = %d, want 1", es.endpoint)
	}
	if es.cluster != 0x0006 {
		t.Errorf("cluster = 0x%04X, want 0x0006", es.cluster)
	}
}

func TestEventSource_RegisterEvent(t *testing.T) {
	es := NewEventSource()

	entry := EventEntry{
		ID:            0x00,
		Priority:      EventPriorityInfo,
		ReadPrivilege: PrivilegeView,
	}

	es.RegisterEvent(entry)

	if !es.HasEvent(0x00) {
		t.Error("HasEvent(0x00) = false, want true")
	}
	if es.HasEvent(0x01) {
		t.Error("HasEvent(0x01) = true, want false")
	}
}

func TestEventSource_RegisterEvents(t *testing.T) {
	es := NewEventSource()

	entries := []EventEntry{
		{ID: 0x00, Priority: EventPriorityCritical},
		{ID: 0x01, Priority: EventPriorityInfo},
		{ID: 0x02, Priority: EventPriorityDebug},
	}

	es.RegisterEvents(entries)

	for _, entry := range entries {
		if !es.HasEvent(entry.ID) {
			t.Errorf("HasEvent(0x%02X) = false, want true", entry.ID)
		}
	}
}

func TestEventSource_Emit(t *testing.T) {
	es := NewEventSource()
	pub := &mockEventPublisher{}

	es.Bind(1, 0x0006, pub)
	es.RegisterEvent(EventEntry{ID: 0x00})

	type testPayload struct {
		Value uint32 `tlv:"0"`
	}

	payload := testPayload{Value: 42}
	num, err := es.Emit(0x00, EventPriorityInfo, payload)

	if err != nil {
		t.Fatalf("Emit() error = %v", err)
	}
	if num != 1 {
		t.Errorf("EventNumber = %d, want 1", num)
	}

	if len(pub.published) != 1 {
		t.Fatalf("published count = %d, want 1", len(pub.published))
	}

	evt := pub.published[0]
	if evt.endpoint != 1 {
		t.Errorf("endpoint = %d, want 1", evt.endpoint)
	}
	if evt.cluster != 0x0006 {
		t.Errorf("cluster = 0x%04X, want 0x0006", evt.cluster)
	}
	if evt.eventID != 0x00 {
		t.Errorf("eventID = 0x%02X, want 0x00", evt.eventID)
	}
	if evt.priority != EventPriorityInfo {
		t.Errorf("priority = %v, want Info", evt.priority)
	}
	if evt.fabricIndex != 0 {
		t.Errorf("fabricIndex = %d, want 0", evt.fabricIndex)
	}
}

func TestEventSource_EmitFabricScoped(t *testing.T) {
	es := NewEventSource()
	pub := &mockEventPublisher{}

	es.Bind(1, 0x0006, pub)
	es.RegisterEvent(EventEntry{ID: 0x00})

	type testPayload struct {
		Value string `tlv:"0"`
	}

	payload := testPayload{Value: "test"}
	num, err := es.EmitFabricScoped(0x00, EventPriorityCritical, payload, 3)

	if err != nil {
		t.Fatalf("EmitFabricScoped() error = %v", err)
	}
	if num != 1 {
		t.Errorf("EventNumber = %d, want 1", num)
	}

	evt := pub.published[0]
	if evt.fabricIndex != 3 {
		t.Errorf("fabricIndex = %d, want 3", evt.fabricIndex)
	}
	if evt.priority != EventPriorityCritical {
		t.Errorf("priority = %v, want Critical", evt.priority)
	}
}

func TestEventSource_Emit_NotBound(t *testing.T) {
	es := NewEventSource()

	_, err := es.Emit(0x00, EventPriorityInfo, nil)

	if !errors.Is(err, ErrEventPublisherNotBound) {
		t.Errorf("error = %v, want ErrEventPublisherNotBound", err)
	}
}

func TestEventSource_Emit_UnregisteredEvent(t *testing.T) {
	es := NewEventSource()
	pub := &mockEventPublisher{}

	es.Bind(1, 0x0006, pub)
	es.RegisterEvent(EventEntry{ID: 0x00})

	// Try to emit unregistered event 0x01
	_, err := es.Emit(0x01, EventPriorityInfo, nil)

	if !errors.Is(err, ErrEventNotRegistered) {
		t.Errorf("error = %v, want ErrEventNotRegistered", err)
	}

	// Verify nothing was published
	if len(pub.published) != 0 {
		t.Errorf("published count = %d, want 0", len(pub.published))
	}
}

func TestEventSource_Emit_NoValidation(t *testing.T) {
	// When no events are registered, validation is skipped
	es := NewEventSource()
	pub := &mockEventPublisher{}

	es.Bind(1, 0x0006, pub)
	// Don't register any events

	// Should succeed without validation
	_, err := es.Emit(0xFF, EventPriorityInfo, nil)

	if err != nil {
		t.Errorf("Emit() error = %v, want nil (no validation)", err)
	}
}

func TestEventSource_Emit_PublisherError(t *testing.T) {
	es := NewEventSource()
	pub := &mockEventPublisher{
		err: errors.New("encoding failed"),
	}

	es.Bind(1, 0x0006, pub)
	es.RegisterEvent(EventEntry{ID: 0x00})

	_, err := es.Emit(0x00, EventPriorityInfo, nil)

	if err == nil {
		t.Error("Emit() error = nil, want error from publisher")
	}
}

func TestEventSource_ValidEvents(t *testing.T) {
	es := NewEventSource()

	entries := []EventEntry{
		{ID: 0x00},
		{ID: 0x01},
	}
	es.RegisterEvents(entries)

	valid := es.ValidEvents()
	if len(valid) != 2 {
		t.Errorf("ValidEvents() count = %d, want 2", len(valid))
	}
}
