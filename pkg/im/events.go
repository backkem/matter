package im

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/backkem/matter/pkg/im/message"
)

// EventPriority matches the spec event priority levels.
type EventPriority uint8

const (
	EventPriorityDebug    EventPriority = 0
	EventPriorityInfo     EventPriority = 1
	EventPriorityCritical EventPriority = 2
)

// String returns the name of the priority level.
func (p EventPriority) String() string {
	switch p {
	case EventPriorityDebug:
		return "Debug"
	case EventPriorityInfo:
		return "Info"
	case EventPriorityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// EventRecord represents a stored event.
type EventRecord struct {
	// Path identifies the event source.
	Path EventPath

	// EventNumber is the monotonically increasing event counter.
	EventNumber message.EventNumber

	// Priority is the event priority level.
	Priority EventPriority

	// Timestamp when the event was generated.
	Timestamp time.Time

	// Data is the raw TLV-encoded event data.
	Data []byte

	// FabricIndex if the event is fabric-scoped (0 if not).
	FabricIndex uint8
}

// EventPath identifies an event source.
type EventPath struct {
	EndpointID message.EndpointID
	ClusterID  message.ClusterID
	EventID    message.EventID
}

// ToEventPathIB converts to the wire format.
func (p EventPath) ToEventPathIB() message.EventPathIB {
	ep := p.EndpointID
	cl := p.ClusterID
	ev := p.EventID
	return message.EventPathIB{
		Endpoint: &ep,
		Cluster:  &cl,
		Event:    &ev,
	}
}

// EventManagerConfig configures the EventManager.
type EventManagerConfig struct {
	// MaxEvents is the maximum number of events to retain.
	// Oldest events are evicted when this limit is exceeded.
	// Default: 100
	MaxEvents int

	// MaxEventsPerPriority limits events per priority level.
	// Default: 50 per level
	MaxEventsPerPriority int
}

// EventManager manages event generation and storage.
// It maintains a circular buffer of recent events per priority level
// and generates monotonically increasing event numbers.
type EventManager struct {
	config EventManagerConfig

	// Event storage by priority
	debugEvents    []*EventRecord
	infoEvents     []*EventRecord
	criticalEvents []*EventRecord

	// Global event counter (monotonically increasing)
	nextEventNumber uint64

	// Listeners for event notifications
	listeners []EventListener

	mu sync.RWMutex
}

// EventListener is notified when events are generated.
type EventListener interface {
	// OnEvent is called when a new event is recorded.
	OnEvent(record *EventRecord)
}

// NewEventManager creates a new event manager.
func NewEventManager(config EventManagerConfig) *EventManager {
	if config.MaxEvents <= 0 {
		config.MaxEvents = 100
	}
	if config.MaxEventsPerPriority <= 0 {
		config.MaxEventsPerPriority = 50
	}

	return &EventManager{
		config:          config,
		debugEvents:     make([]*EventRecord, 0, config.MaxEventsPerPriority),
		infoEvents:      make([]*EventRecord, 0, config.MaxEventsPerPriority),
		criticalEvents:  make([]*EventRecord, 0, config.MaxEventsPerPriority),
		nextEventNumber: 1, // Event numbers start at 1
	}
}

// AddListener registers a listener for event notifications.
func (m *EventManager) AddListener(listener EventListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, listener)
}

// RemoveListener unregisters a listener.
func (m *EventManager) RemoveListener(listener EventListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, l := range m.listeners {
		if l == listener {
			m.listeners = append(m.listeners[:i], m.listeners[i+1:]...)
			return
		}
	}
}

// PublishEvent generates and stores a new event.
// Returns the assigned event number.
func (m *EventManager) PublishEvent(
	endpointID message.EndpointID,
	clusterID message.ClusterID,
	eventID message.EventID,
	priority EventPriority,
	data []byte,
) message.EventNumber {
	return m.PublishEventWithFabric(endpointID, clusterID, eventID, priority, data, 0)
}

// PublishEventWithFabric generates a fabric-scoped event.
func (m *EventManager) PublishEventWithFabric(
	endpointID message.EndpointID,
	clusterID message.ClusterID,
	eventID message.EventID,
	priority EventPriority,
	data []byte,
	fabricIndex uint8,
) message.EventNumber {
	m.mu.Lock()

	// Allocate event number atomically
	eventNum := message.EventNumber(atomic.AddUint64(&m.nextEventNumber, 1) - 1)

	record := &EventRecord{
		Path: EventPath{
			EndpointID: endpointID,
			ClusterID:  clusterID,
			EventID:    eventID,
		},
		EventNumber: eventNum,
		Priority:    priority,
		Timestamp:   time.Now(),
		Data:        data,
		FabricIndex: fabricIndex,
	}

	// Store in appropriate priority queue
	switch priority {
	case EventPriorityDebug:
		m.debugEvents = m.appendEvent(m.debugEvents, record)
	case EventPriorityInfo:
		m.infoEvents = m.appendEvent(m.infoEvents, record)
	case EventPriorityCritical:
		m.criticalEvents = m.appendEvent(m.criticalEvents, record)
	}

	// Copy listeners for notification outside lock
	listeners := make([]EventListener, len(m.listeners))
	copy(listeners, m.listeners)

	m.mu.Unlock()

	// Notify listeners
	for _, listener := range listeners {
		listener.OnEvent(record)
	}

	return eventNum
}

// appendEvent adds a record to the priority queue, evicting oldest if needed.
func (m *EventManager) appendEvent(queue []*EventRecord, record *EventRecord) []*EventRecord {
	if len(queue) >= m.config.MaxEventsPerPriority {
		// Evict oldest (first element)
		queue = queue[1:]
	}
	return append(queue, record)
}

// GetEvents returns events matching the filter criteria.
func (m *EventManager) GetEvents(
	path *EventPath,
	minEventNumber *message.EventNumber,
	fabricIndex uint8,
	priorities []EventPriority,
) []*EventRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*EventRecord

	// Determine which priority queues to search
	if len(priorities) == 0 {
		priorities = []EventPriority{EventPriorityDebug, EventPriorityInfo, EventPriorityCritical}
	}

	for _, priority := range priorities {
		var queue []*EventRecord
		switch priority {
		case EventPriorityDebug:
			queue = m.debugEvents
		case EventPriorityInfo:
			queue = m.infoEvents
		case EventPriorityCritical:
			queue = m.criticalEvents
		}

		for _, record := range queue {
			if m.matchesFilter(record, path, minEventNumber, fabricIndex) {
				result = append(result, record)
			}
		}
	}

	return result
}

// matchesFilter checks if a record matches the filter criteria.
func (m *EventManager) matchesFilter(
	record *EventRecord,
	path *EventPath,
	minEventNumber *message.EventNumber,
	fabricIndex uint8,
) bool {
	// Check event number filter
	if minEventNumber != nil && record.EventNumber < *minEventNumber {
		return false
	}

	// Check fabric filter
	if fabricIndex != 0 && record.FabricIndex != 0 && record.FabricIndex != fabricIndex {
		return false
	}

	// Check path filter
	if path != nil {
		if path.EndpointID != record.Path.EndpointID {
			return false
		}
		if path.ClusterID != record.Path.ClusterID {
			return false
		}
		if path.EventID != record.Path.EventID {
			return false
		}
	}

	return true
}

// GetLatestEventNumber returns the most recent event number.
func (m *EventManager) GetLatestEventNumber() message.EventNumber {
	return message.EventNumber(atomic.LoadUint64(&m.nextEventNumber) - 1)
}

// Clear removes all stored events.
func (m *EventManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.debugEvents = m.debugEvents[:0]
	m.infoEvents = m.infoEvents[:0]
	m.criticalEvents = m.criticalEvents[:0]
}

// ToEventDataIB converts an EventRecord to wire format.
func (r *EventRecord) ToEventDataIB() message.EventDataIB {
	ib := message.EventDataIB{
		Path:        r.Path.ToEventPathIB(),
		EventNumber: r.EventNumber,
		Priority:    uint8(r.Priority),
		Data:        r.Data,
	}

	// Set epoch timestamp
	epochMs := uint64(r.Timestamp.UnixMilli())
	ib.EpochTimestamp = &epochMs

	return ib
}

// ToEventReportIB converts an EventRecord to a report IB.
func (r *EventRecord) ToEventReportIB() message.EventReportIB {
	data := r.ToEventDataIB()
	return message.EventReportIB{
		EventData: &data,
	}
}

// EventReporter provides methods to build event report messages.
type EventReporter struct {
	eventManager *EventManager
}

// NewEventReporter creates a new event reporter.
func NewEventReporter(em *EventManager) *EventReporter {
	return &EventReporter{eventManager: em}
}

// BuildReportData creates a ReportDataMessage containing events.
func (r *EventReporter) BuildReportData(
	events []*EventRecord,
	subscriptionID *message.SubscriptionID,
	suppressResponse bool,
) *message.ReportDataMessage {
	msg := &message.ReportDataMessage{
		SubscriptionID:   subscriptionID,
		SuppressResponse: suppressResponse,
	}

	for _, record := range events {
		msg.EventReports = append(msg.EventReports, record.ToEventReportIB())
	}

	return msg
}

// BuildUnsolicitedReport creates an unsolicited report for new events.
// This is used when events need to be pushed immediately (e.g., PushTransportBegin).
func (r *EventReporter) BuildUnsolicitedReport(
	events []*EventRecord,
) *message.ReportDataMessage {
	return r.BuildReportData(events, nil, true)
}
