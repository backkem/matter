package datamodel

import "github.com/backkem/matter/pkg/fabric"

// SubjectDescriptor contains authentication information about the request source.
// This is used for ACL validation.
type SubjectDescriptor struct {
	// FabricIndex identifies the fabric the subject belongs to.
	FabricIndex fabric.FabricIndex

	// NodeID is the operational node ID of the subject.
	NodeID uint64

	// AuthMode indicates how the subject was authenticated.
	AuthMode AuthMode

	// CATTags contains the CASE Authenticated Tags for the subject.
	CATTags []uint32
}

// OperationFlags contains common flags for data model operations.
type OperationFlags uint32

const (
	// OpFlagInternal indicates an internal operation that bypasses ACL checks.
	// Used for operations initiated by the node itself, not external requests.
	OpFlagInternal OperationFlags = 1 << iota
)

// Has returns true if the flags contain the specified flag(s).
func (f OperationFlags) Has(flag OperationFlags) bool {
	return f&flag != 0
}

// ReadFlags contains flags specific to read operations.
type ReadFlags uint32

const (
	// ReadFlagFabricFiltered indicates the read is fabric-filtered.
	// Only fabric-scoped data for the accessing fabric will be returned.
	ReadFlagFabricFiltered ReadFlags = 1 << iota

	// ReadFlagAllowsLargePayload indicates the transport supports large payloads.
	ReadFlagAllowsLargePayload
)

// Has returns true if the flags contain the specified flag(s).
func (f ReadFlags) Has(flag ReadFlags) bool {
	return f&flag != 0
}

// WriteFlags contains flags specific to write operations.
type WriteFlags uint32

const (
	// WriteFlagTimed indicates the write is part of a timed interaction.
	WriteFlagTimed WriteFlags = 1 << iota
)

// Has returns true if the flags contain the specified flag(s).
func (f WriteFlags) Has(flag WriteFlags) bool {
	return f&flag != 0
}

// InvokeFlags contains flags specific to invoke operations.
type InvokeFlags uint32

const (
	// InvokeFlagTimed indicates the invoke is part of a timed interaction.
	InvokeFlagTimed InvokeFlags = 1 << iota
)

// Has returns true if the flags contain the specified flag(s).
func (f InvokeFlags) Has(flag InvokeFlags) bool {
	return f&flag != 0
}

// ReadAttributeRequest contains parameters for reading an attribute.
type ReadAttributeRequest struct {
	// Path identifies the attribute to read.
	Path ConcreteAttributePath

	// OperationFlags contains common operation flags.
	OperationFlags OperationFlags

	// ReadFlags contains read-specific flags.
	ReadFlags ReadFlags

	// Subject contains authentication info for the request source.
	// nil for internal operations.
	Subject *SubjectDescriptor
}

// FabricIndex returns the accessing fabric index, or 0 if none.
func (r *ReadAttributeRequest) FabricIndex() fabric.FabricIndex {
	if r.Subject == nil {
		return 0
	}
	return r.Subject.FabricIndex
}

// IsFabricFiltered returns true if the read is fabric-filtered.
func (r *ReadAttributeRequest) IsFabricFiltered() bool {
	return r.ReadFlags.Has(ReadFlagFabricFiltered)
}

// IsInternal returns true if this is an internal operation.
func (r *ReadAttributeRequest) IsInternal() bool {
	return r.OperationFlags.Has(OpFlagInternal)
}

// WriteAttributeRequest contains parameters for writing an attribute.
type WriteAttributeRequest struct {
	// Path identifies the attribute to write.
	// For list operations, this includes the list index.
	Path ConcreteDataAttributePath

	// OperationFlags contains common operation flags.
	OperationFlags OperationFlags

	// WriteFlags contains write-specific flags.
	WriteFlags WriteFlags

	// Subject contains authentication info for the request source.
	// nil for internal operations.
	Subject *SubjectDescriptor

	// DataVersion is the expected data version for optimistic locking.
	// nil means no version check.
	DataVersion *DataVersion
}

// FabricIndex returns the accessing fabric index, or 0 if none.
func (r *WriteAttributeRequest) FabricIndex() fabric.FabricIndex {
	if r.Subject == nil {
		return 0
	}
	return r.Subject.FabricIndex
}

// IsTimed returns true if this is a timed write.
func (r *WriteAttributeRequest) IsTimed() bool {
	return r.WriteFlags.Has(WriteFlagTimed)
}

// IsInternal returns true if this is an internal operation.
func (r *WriteAttributeRequest) IsInternal() bool {
	return r.OperationFlags.Has(OpFlagInternal)
}

// IsListOperation returns true if this is a list element operation.
func (r *WriteAttributeRequest) IsListOperation() bool {
	return r.Path.ListIndex != nil
}

// InvokeRequest contains parameters for invoking a command.
type InvokeRequest struct {
	// Path identifies the command to invoke.
	Path ConcreteCommandPath

	// OperationFlags contains common operation flags.
	OperationFlags OperationFlags

	// InvokeFlags contains invoke-specific flags.
	InvokeFlags InvokeFlags

	// Subject contains authentication info for the request source.
	// nil for internal operations.
	Subject *SubjectDescriptor
}

// FabricIndex returns the accessing fabric index, or 0 if none.
func (r *InvokeRequest) FabricIndex() fabric.FabricIndex {
	if r.Subject == nil {
		return 0
	}
	return r.Subject.FabricIndex
}

// IsTimed returns true if this is a timed invoke.
func (r *InvokeRequest) IsTimed() bool {
	return r.InvokeFlags.Has(InvokeFlagTimed)
}

// IsInternal returns true if this is an internal operation.
func (r *InvokeRequest) IsInternal() bool {
	return r.OperationFlags.Has(OpFlagInternal)
}

// EventReadRequest contains parameters for reading events.
type EventReadRequest struct {
	// Path identifies the event to read.
	Path ConcreteEventPath

	// OperationFlags contains common operation flags.
	OperationFlags OperationFlags

	// Subject contains authentication info for the request source.
	Subject *SubjectDescriptor

	// MinEventNumber is the minimum event number to return.
	// Events with numbers less than this are filtered out.
	MinEventNumber *EventNumber
}

// FabricIndex returns the accessing fabric index, or 0 if none.
func (r *EventReadRequest) FabricIndex() fabric.FabricIndex {
	if r.Subject == nil {
		return 0
	}
	return r.Subject.FabricIndex
}

// ListWriteOperation indicates the type of list write notification.
type ListWriteOperation int

const (
	// ListWriteBegin indicates the start of a list write operation.
	ListWriteBegin ListWriteOperation = iota

	// ListWriteSuccess indicates the list write completed successfully.
	ListWriteSuccess

	// ListWriteFailure indicates the list write failed.
	ListWriteFailure
)

// String returns a human-readable name for the operation.
func (o ListWriteOperation) String() string {
	switch o {
	case ListWriteBegin:
		return "Begin"
	case ListWriteSuccess:
		return "Success"
	case ListWriteFailure:
		return "Failure"
	default:
		return "Unknown"
	}
}
