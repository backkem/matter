package basic

import (
	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// StartUpEvent is emitted after boot or reboot (Spec 11.1.6.1).
// Priority: CRITICAL, Conformance: Mandatory
type StartUpEvent struct {
	SoftwareVersion uint32
}

// MarshalTLV implements the TLVMarshaler interface.
func (e StartUpEvent) MarshalTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}
	if err := w.PutUint(tlv.ContextTag(0), uint64(e.SoftwareVersion)); err != nil {
		return err
	}
	return w.EndContainer()
}

// ShutDownEvent is emitted before orderly shutdown (Spec 11.1.6.2).
// Priority: CRITICAL, Conformance: Optional
type ShutDownEvent struct{}

// MarshalTLV implements the TLVMarshaler interface.
func (e ShutDownEvent) MarshalTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}
	return w.EndContainer()
}

// LeaveEvent is emitted when leaving a fabric (Spec 11.1.6.3).
// Priority: INFO, Conformance: Optional
type LeaveEvent struct {
	FabricIndex uint8
}

// MarshalTLV implements the TLVMarshaler interface.
func (e LeaveEvent) MarshalTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}
	if err := w.PutUint(tlv.ContextTag(0), uint64(e.FabricIndex)); err != nil {
		return err
	}
	return w.EndContainer()
}

// ReachableChangedEvent is emitted when Reachable attribute changes (Spec 11.1.6.4).
// Priority: INFO, Conformance: Reachable attribute
type ReachableChangedEvent struct {
	ReachableNewValue bool
}

// MarshalTLV implements the TLVMarshaler interface.
func (e ReachableChangedEvent) MarshalTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}
	if err := w.PutBool(tlv.ContextTag(0), e.ReachableNewValue); err != nil {
		return err
	}
	return w.EndContainer()
}

// EmitStartUp emits the StartUp event.
// This should be called after completing a boot or reboot process.
//
// Spec: Section 11.1.6.1
func (c *Cluster) EmitStartUp() (datamodel.EventNumber, error) {
	if !c.EventSource.IsBound() {
		return 0, nil // No publisher, silently skip
	}

	event := StartUpEvent{
		SoftwareVersion: c.config.DeviceInfo.SoftwareVersion,
	}

	return c.EventSource.Emit(EventStartUp, datamodel.EventPriorityCritical, event)
}

// EmitShutDown emits the ShutDown event.
// This should be called before any orderly shutdown sequence.
//
// Spec: Section 11.1.6.2
func (c *Cluster) EmitShutDown() (datamodel.EventNumber, error) {
	if !c.EventSource.IsBound() {
		return 0, nil // No publisher, silently skip
	}

	return c.EventSource.Emit(EventShutDown, datamodel.EventPriorityCritical, ShutDownEvent{})
}

// EmitLeave emits the Leave event.
// This should be called before permanently leaving a fabric.
//
// Spec: Section 11.1.6.3
func (c *Cluster) EmitLeave(fabricIndex uint8) (datamodel.EventNumber, error) {
	if !c.EventSource.IsBound() {
		return 0, nil // No publisher, silently skip
	}

	event := LeaveEvent{
		FabricIndex: fabricIndex,
	}

	return c.EventSource.Emit(EventLeave, datamodel.EventPriorityInfo, event)
}

// EmitReachableChanged emits the ReachableChanged event.
// This should be called when the Reachable attribute changes.
//
// Spec: Section 11.1.6.4
func (c *Cluster) EmitReachableChanged(newValue bool) (datamodel.EventNumber, error) {
	if !c.EventSource.IsBound() {
		return 0, nil // No publisher, silently skip
	}

	if c.config.DeviceInfo.Reachable == nil {
		return 0, nil // Reachable not supported
	}

	event := ReachableChangedEvent{
		ReachableNewValue: newValue,
	}

	return c.EventSource.Emit(EventReachableChanged, datamodel.EventPriorityInfo, event)
}
