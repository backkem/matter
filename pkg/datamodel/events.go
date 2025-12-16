package datamodel

import (
	"errors"
	"fmt"
)

// EventPublisher abstracts the IM engine's event manager.
// It accepts Go structs with tlv tags - TLV encoding is handled centrally
// by the publisher implementation, not by individual clusters.
//
// This design ensures consistent encoding rules across all clusters
// and avoids code duplication.
type EventPublisher interface {
	// PublishEvent emits an event. The data parameter is a Go struct
	// with tlv struct tags that will be TLV-encoded by the publisher.
	// Returns the assigned EventNumber, or error if encoding fails.
	//
	// Parameters:
	//   - endpoint: The endpoint emitting the event
	//   - cluster: The cluster emitting the event
	//   - eventID: The event identifier within the cluster
	//   - priority: Event priority (Debug, Info, Critical)
	//   - data: Go struct with tlv tags (NOT []byte)
	//   - fabricIndex: Fabric scope (0 for non-fabric-scoped events)
	PublishEvent(
		endpoint EndpointID,
		cluster ClusterID,
		eventID EventID,
		priority EventPriority,
		data interface{},
		fabricIndex uint8,
	) (EventNumber, error)
}

// EventSource is a mixin to add event capabilities to any cluster.
// Embed this alongside ClusterBase for clusters that emit events.
//
// Design notes:
//   - Uses composition, not inheritance (embed alongside ClusterBase)
//   - Internal event validation via validEvents map
//   - EventList (0xFFFA) is deprecated in Matter 1.3+, so validEvents
//     is NOT exposed as a readable attribute by default
//
// Example usage:
//
//	type MyCluster struct {
//	    *datamodel.ClusterBase
//	    *datamodel.EventSource  // Composition
//	}
type EventSource struct {
	endpoint  EndpointID
	cluster   ClusterID
	publisher EventPublisher

	// Internal validation - NOT exposed as attribute 0xFFFA (deprecated in Matter 1.3+)
	// Used to validate that emitted event IDs are registered for this cluster.
	validEvents map[EventID]EventEntry
}

// NewEventSource creates a new EventSource.
// Call Bind() to connect it to a cluster and publisher.
func NewEventSource() *EventSource {
	return &EventSource{
		validEvents: make(map[EventID]EventEntry),
	}
}

// Bind connects the EventSource to its parent cluster and publisher.
// This should be called during cluster initialization.
func (e *EventSource) Bind(endpoint EndpointID, cluster ClusterID, publisher EventPublisher) {
	e.endpoint = endpoint
	e.cluster = cluster
	e.publisher = publisher
}

// RegisterEvent adds an event to internal validation.
// This is used to validate that only registered events are emitted.
// Note: This does NOT expose the event via attribute 0xFFFA (deprecated).
func (e *EventSource) RegisterEvent(entry EventEntry) {
	if e.validEvents == nil {
		e.validEvents = make(map[EventID]EventEntry)
	}
	e.validEvents[entry.ID] = entry
}

// RegisterEvents adds multiple events to internal validation.
func (e *EventSource) RegisterEvents(entries []EventEntry) {
	for _, entry := range entries {
		e.RegisterEvent(entry)
	}
}

// ValidEvents returns the registered events for internal use.
// This is NOT for exposing as attribute 0xFFFA.
func (e *EventSource) ValidEvents() map[EventID]EventEntry {
	return e.validEvents
}

// HasEvent returns true if the event ID is registered.
func (e *EventSource) HasEvent(eventID EventID) bool {
	if e.validEvents == nil {
		return false
	}
	_, ok := e.validEvents[eventID]
	return ok
}

// Emit publishes an event with the given payload struct.
// The payload should be a Go struct with tlv tags.
// FabricIndex defaults to 0 (all fabrics); use EmitFabricScoped for fabric-specific.
//
// Returns the assigned EventNumber, or error if:
//   - Publisher is not bound
//   - Event ID is not registered (if validation is enabled)
//   - TLV encoding fails (in the publisher)
func (e *EventSource) Emit(eventID EventID, priority EventPriority, payload interface{}) (EventNumber, error) {
	return e.EmitFabricScoped(eventID, priority, payload, 0)
}

// EmitFabricScoped publishes a fabric-scoped event.
// Use this for events that should only be visible to a specific fabric.
func (e *EventSource) EmitFabricScoped(eventID EventID, priority EventPriority, payload interface{}, fabricIndex uint8) (EventNumber, error) {
	if e.publisher == nil {
		return 0, ErrEventPublisherNotBound
	}

	// Validate event ID if validation is enabled
	if e.validEvents != nil && len(e.validEvents) > 0 {
		if _, ok := e.validEvents[eventID]; !ok {
			return 0, fmt.Errorf("%w: event ID 0x%04X not registered for cluster 0x%04X",
				ErrEventNotRegistered, eventID, e.cluster)
		}
	}

	return e.publisher.PublishEvent(e.endpoint, e.cluster, eventID, priority, payload, fabricIndex)
}

// IsBound returns true if the EventSource is bound to a publisher.
func (e *EventSource) IsBound() bool {
	return e.publisher != nil
}

// Event source errors.
var (
	ErrEventPublisherNotBound = errors.New("event publisher not bound")
	ErrEventNotRegistered     = errors.New("event not registered")
)
