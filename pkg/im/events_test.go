package im

import (
	"sync"
	"testing"
	"time"

	"github.com/backkem/matter/pkg/im/message"
)

func TestEventManager_PublishEvent(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})

	eventNum := em.PublishEvent(
		1,      // endpoint
		0x0006, // cluster (OnOff)
		0x0000, // event ID
		EventPriorityInfo,
		[]byte{0x01}, // data
	)

	if eventNum != 1 {
		t.Errorf("expected event number 1, got %d", eventNum)
	}

	// Publish another event
	eventNum2 := em.PublishEvent(
		1,
		0x0006,
		0x0001,
		EventPriorityCritical,
		[]byte{0x02},
	)

	if eventNum2 != 2 {
		t.Errorf("expected event number 2, got %d", eventNum2)
	}

	// Verify latest event number
	if em.GetLatestEventNumber() != 2 {
		t.Errorf("expected latest event number 2, got %d", em.GetLatestEventNumber())
	}
}

func TestEventManager_GetEvents(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})

	// Publish events at different priorities
	em.PublishEvent(1, 0x0006, 0x00, EventPriorityDebug, nil)
	em.PublishEvent(1, 0x0006, 0x01, EventPriorityInfo, nil)
	em.PublishEvent(1, 0x0006, 0x02, EventPriorityCritical, nil)

	// Get all events
	events := em.GetEvents(nil, nil, 0, nil)
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}

	// Get only Info priority
	infoEvents := em.GetEvents(nil, nil, 0, []EventPriority{EventPriorityInfo})
	if len(infoEvents) != 1 {
		t.Errorf("expected 1 info event, got %d", len(infoEvents))
	}

	// Get by min event number
	minNum := message.EventNumber(2)
	filteredEvents := em.GetEvents(nil, &minNum, 0, nil)
	if len(filteredEvents) != 2 {
		t.Errorf("expected 2 events with number >= 2, got %d", len(filteredEvents))
	}
}

func TestEventManager_GetEvents_PathFilter(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})

	// Publish events on different clusters
	em.PublishEvent(1, 0x0006, 0x00, EventPriorityInfo, nil) // OnOff
	em.PublishEvent(1, 0x0008, 0x00, EventPriorityInfo, nil) // LevelControl
	em.PublishEvent(2, 0x0006, 0x00, EventPriorityInfo, nil) // OnOff on endpoint 2

	// Filter by path
	path := &EventPath{
		EndpointID: 1,
		ClusterID:  0x0006,
		EventID:    0x00,
	}
	events := em.GetEvents(path, nil, 0, nil)
	if len(events) != 1 {
		t.Errorf("expected 1 event matching path, got %d", len(events))
	}
}

func TestEventManager_FabricFiltering(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})

	// Publish fabric-scoped events
	em.PublishEventWithFabric(1, 0x0006, 0x00, EventPriorityInfo, nil, 1)
	em.PublishEventWithFabric(1, 0x0006, 0x00, EventPriorityInfo, nil, 2)
	em.PublishEventWithFabric(1, 0x0006, 0x00, EventPriorityInfo, nil, 0) // Not fabric-scoped

	// Get events for fabric 1
	events := em.GetEvents(nil, nil, 1, nil)
	if len(events) != 2 { // Fabric 1 events + non-fabric-scoped
		t.Errorf("expected 2 events for fabric 1, got %d", len(events))
	}

	// Get events for fabric 2
	events2 := em.GetEvents(nil, nil, 2, nil)
	if len(events2) != 2 { // Fabric 2 events + non-fabric-scoped
		t.Errorf("expected 2 events for fabric 2, got %d", len(events2))
	}
}

func TestEventManager_Eviction(t *testing.T) {
	em := NewEventManager(EventManagerConfig{
		MaxEventsPerPriority: 3,
	})

	// Publish 5 events (exceeds limit of 3)
	for i := 0; i < 5; i++ {
		em.PublishEvent(1, 0x0006, message.EventID(i), EventPriorityInfo, nil)
	}

	// Should only have 3 events (oldest evicted)
	events := em.GetEvents(nil, nil, 0, nil)
	if len(events) != 3 {
		t.Errorf("expected 3 events after eviction, got %d", len(events))
	}

	// Oldest event should be event 3 (0, 1 evicted)
	if events[0].EventNumber != 3 {
		t.Errorf("expected first event to be number 3, got %d", events[0].EventNumber)
	}
}

func TestEventManager_Listener(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})

	var received []*EventRecord
	var mu sync.Mutex

	listener := &testListener{
		onEvent: func(r *EventRecord) {
			mu.Lock()
			received = append(received, r)
			mu.Unlock()
		},
	}

	em.AddListener(listener)

	// Publish event
	em.PublishEvent(1, 0x0006, 0x00, EventPriorityInfo, []byte{0x42})

	// Give listener time to be called
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	if len(received) != 1 {
		t.Errorf("expected 1 received event, got %d", len(received))
	}
	if received[0].Data[0] != 0x42 {
		t.Errorf("expected data 0x42, got 0x%x", received[0].Data[0])
	}
	mu.Unlock()

	// Remove listener
	em.RemoveListener(listener)

	// Publish another event
	em.PublishEvent(1, 0x0006, 0x01, EventPriorityInfo, nil)

	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	if len(received) != 1 {
		t.Errorf("expected still 1 received event after removal, got %d", len(received))
	}
	mu.Unlock()
}

func TestEventManager_Clear(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})

	em.PublishEvent(1, 0x0006, 0x00, EventPriorityDebug, nil)
	em.PublishEvent(1, 0x0006, 0x01, EventPriorityInfo, nil)
	em.PublishEvent(1, 0x0006, 0x02, EventPriorityCritical, nil)

	em.Clear()

	events := em.GetEvents(nil, nil, 0, nil)
	if len(events) != 0 {
		t.Errorf("expected 0 events after clear, got %d", len(events))
	}

	// Event numbers should continue (not reset)
	nextNum := em.PublishEvent(1, 0x0006, 0x00, EventPriorityInfo, nil)
	if nextNum != 4 {
		t.Errorf("expected event number 4 after clear, got %d", nextNum)
	}
}

func TestEventRecord_ToEventDataIB(t *testing.T) {
	record := &EventRecord{
		Path: EventPath{
			EndpointID: 1,
			ClusterID:  0x0006,
			EventID:    0x0000,
		},
		EventNumber: 42,
		Priority:    EventPriorityInfo,
		Timestamp:   time.Now(),
		Data:        []byte{0x01, 0x02, 0x03},
	}

	ib := record.ToEventDataIB()

	if ib.EventNumber != 42 {
		t.Errorf("expected event number 42, got %d", ib.EventNumber)
	}
	if ib.Priority != uint8(EventPriorityInfo) {
		t.Errorf("expected priority %d, got %d", EventPriorityInfo, ib.Priority)
	}
	if *ib.Path.Endpoint != 1 {
		t.Errorf("expected endpoint 1, got %d", *ib.Path.Endpoint)
	}
	if *ib.Path.Cluster != 0x0006 {
		t.Errorf("expected cluster 0x0006, got 0x%x", *ib.Path.Cluster)
	}
	if *ib.Path.Event != 0x0000 {
		t.Errorf("expected event 0x0000, got 0x%x", *ib.Path.Event)
	}
	if ib.EpochTimestamp == nil {
		t.Error("expected EpochTimestamp to be set")
	}
}

func TestEventReporter_BuildReportData(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})
	reporter := NewEventReporter(em)

	em.PublishEvent(1, 0x0006, 0x00, EventPriorityInfo, []byte{0x01})
	em.PublishEvent(1, 0x0006, 0x01, EventPriorityInfo, []byte{0x02})

	events := em.GetEvents(nil, nil, 0, nil)
	subID := message.SubscriptionID(12345)

	msg := reporter.BuildReportData(events, &subID, false)

	if len(msg.EventReports) != 2 {
		t.Errorf("expected 2 event reports, got %d", len(msg.EventReports))
	}
	if msg.SubscriptionID == nil || *msg.SubscriptionID != subID {
		t.Error("subscription ID mismatch")
	}
	if msg.SuppressResponse {
		t.Error("expected SuppressResponse=false")
	}
}

func TestEventReporter_BuildUnsolicitedReport(t *testing.T) {
	em := NewEventManager(EventManagerConfig{})
	reporter := NewEventReporter(em)

	em.PublishEvent(1, 0x0006, 0x00, EventPriorityCritical, []byte{0xFF})

	events := em.GetEvents(nil, nil, 0, nil)
	msg := reporter.BuildUnsolicitedReport(events)

	if len(msg.EventReports) != 1 {
		t.Errorf("expected 1 event report, got %d", len(msg.EventReports))
	}
	if msg.SubscriptionID != nil {
		t.Error("expected no subscription ID for unsolicited report")
	}
	if !msg.SuppressResponse {
		t.Error("expected SuppressResponse=true for unsolicited report")
	}
}

func TestEventPriority_String(t *testing.T) {
	tests := []struct {
		p    EventPriority
		want string
	}{
		{EventPriorityDebug, "Debug"},
		{EventPriorityInfo, "Info"},
		{EventPriorityCritical, "Critical"},
		{EventPriority(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.p.String(); got != tt.want {
			t.Errorf("EventPriority(%d).String() = %q, want %q", tt.p, got, tt.want)
		}
	}
}

func TestEventPath_ToEventPathIB(t *testing.T) {
	path := EventPath{
		EndpointID: 5,
		ClusterID:  0x0101,
		EventID:    0x0002,
	}

	ib := path.ToEventPathIB()

	if ib.Endpoint == nil || *ib.Endpoint != 5 {
		t.Error("endpoint mismatch")
	}
	if ib.Cluster == nil || *ib.Cluster != 0x0101 {
		t.Error("cluster mismatch")
	}
	if ib.Event == nil || *ib.Event != 0x0002 {
		t.Error("event mismatch")
	}
}

// Test helpers

type testListener struct {
	onEvent func(*EventRecord)
}

func (l *testListener) OnEvent(r *EventRecord) {
	if l.onEvent != nil {
		l.onEvent(r)
	}
}
