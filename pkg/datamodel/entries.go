package datamodel

// AttributeEntry describes an attribute's metadata.
// Used for discovery and ACL validation.
// C++ Reference: MetadataTypes.h::AttributeEntry
type AttributeEntry struct {
	// ID is the attribute identifier.
	ID AttributeID

	// Quality contains the attribute quality flags.
	Quality AttributeQuality

	// ReadPrivilege is the minimum privilege required to read this attribute.
	// nil indicates the attribute is not readable.
	ReadPrivilege *Privilege

	// WritePrivilege is the minimum privilege required to write this attribute.
	// nil indicates the attribute is not writable.
	WritePrivilege *Privilege
}

// IsReadable returns true if the attribute can be read.
func (a *AttributeEntry) IsReadable() bool {
	return a.ReadPrivilege != nil
}

// IsWritable returns true if the attribute can be written.
func (a *AttributeEntry) IsWritable() bool {
	return a.WritePrivilege != nil
}

// HasQuality returns true if the attribute has the specified quality flag(s).
func (a *AttributeEntry) HasQuality(q AttributeQuality) bool {
	return a.Quality&q != 0
}

// IsList returns true if this is a list attribute.
func (a *AttributeEntry) IsList() bool {
	return a.HasQuality(AttrQualityList)
}

// IsFabricScoped returns true if this attribute is fabric-scoped.
func (a *AttributeEntry) IsFabricScoped() bool {
	return a.HasQuality(AttrQualityFabricScoped)
}

// IsFabricSensitive returns true if this attribute is fabric-sensitive.
func (a *AttributeEntry) IsFabricSensitive() bool {
	return a.HasQuality(AttrQualityFabricSensitive)
}

// RequiresTimed returns true if this attribute requires timed writes.
func (a *AttributeEntry) RequiresTimed() bool {
	return a.HasQuality(AttrQualityTimed)
}

// RequiresAtomic returns true if this attribute requires atomic writes.
func (a *AttributeEntry) RequiresAtomic() bool {
	return a.HasQuality(AttrQualityAtomic)
}

// CommandEntry describes a command's metadata.
// Used for discovery and ACL validation.
// C++ Reference: MetadataTypes.h::AcceptedCommandEntry
type CommandEntry struct {
	// ID is the command identifier.
	ID CommandID

	// Quality contains the command quality flags.
	Quality CommandQuality

	// InvokePrivilege is the minimum privilege required to invoke this command.
	InvokePrivilege Privilege
}

// HasQuality returns true if the command has the specified quality flag(s).
func (c *CommandEntry) HasQuality(q CommandQuality) bool {
	return c.Quality&q != 0
}

// IsFabricScoped returns true if this command is fabric-scoped.
func (c *CommandEntry) IsFabricScoped() bool {
	return c.HasQuality(CmdQualityFabricScoped)
}

// RequiresTimed returns true if this command requires timed interaction.
func (c *CommandEntry) RequiresTimed() bool {
	return c.HasQuality(CmdQualityTimed)
}

// IsLargeMessage returns true if this command may exceed minimum MTU.
func (c *CommandEntry) IsLargeMessage() bool {
	return c.HasQuality(CmdQualityLargeMessage)
}

// EventEntry describes an event's metadata.
// Used for discovery and ACL validation.
// C++ Reference: MetadataTypes.h::EventEntry
type EventEntry struct {
	// ID is the event identifier.
	ID EventID

	// Priority is the default priority for this event.
	Priority EventPriority

	// ReadPrivilege is the minimum privilege required to read this event.
	ReadPrivilege Privilege

	// IsFabricSensitive indicates if the event is fabric-sensitive.
	IsFabricSensitive bool
}

// EndpointEntry describes an endpoint's metadata.
// C++ Reference: MetadataTypes.h::EndpointEntry
type EndpointEntry struct {
	// ID is the endpoint identifier.
	ID EndpointID

	// ParentID is the parent endpoint ID.
	// nil indicates endpoint 0 is the parent (for non-root endpoints)
	// or there is no parent (for endpoint 0).
	ParentID *EndpointID

	// CompositionPattern defines how child endpoints are organized.
	CompositionPattern EndpointComposition
}

// DeviceTypeEntry describes a device type present on an endpoint.
// C++ Reference: MetadataTypes.h::DeviceTypeEntry
type DeviceTypeEntry struct {
	// DeviceTypeID is the device type identifier.
	DeviceTypeID DeviceTypeID

	// Revision is the device type revision.
	Revision uint8
}

// ServerClusterEntry describes a server cluster on an endpoint.
// Used for cluster discovery.
type ServerClusterEntry struct {
	// ClusterID is the cluster identifier.
	ClusterID ClusterID

	// DataVersion is the current data version for the cluster.
	DataVersion DataVersion

	// IsDiagnostics indicates if this is a diagnostics cluster (K quality).
	IsDiagnostics bool
}

// NewAttributeEntry creates a new attribute entry with common defaults.
// readPriv and writePriv can be nil for non-readable/non-writable attributes.
func NewAttributeEntry(id AttributeID, quality AttributeQuality, readPriv, writePriv *Privilege) AttributeEntry {
	return AttributeEntry{
		ID:             id,
		Quality:        quality,
		ReadPrivilege:  readPriv,
		WritePrivilege: writePriv,
	}
}

// NewReadOnlyAttribute creates a read-only attribute entry.
func NewReadOnlyAttribute(id AttributeID, quality AttributeQuality, readPriv Privilege) AttributeEntry {
	return AttributeEntry{
		ID:            id,
		Quality:       quality,
		ReadPrivilege: &readPriv,
	}
}

// NewReadWriteAttribute creates a read-write attribute entry.
func NewReadWriteAttribute(id AttributeID, quality AttributeQuality, readPriv, writePriv Privilege) AttributeEntry {
	return AttributeEntry{
		ID:             id,
		Quality:        quality,
		ReadPrivilege:  &readPriv,
		WritePrivilege: &writePriv,
	}
}

// NewCommandEntry creates a new command entry.
func NewCommandEntry(id CommandID, quality CommandQuality, invokePriv Privilege) CommandEntry {
	return CommandEntry{
		ID:              id,
		Quality:         quality,
		InvokePrivilege: invokePriv,
	}
}

// NewEventEntry creates a new event entry.
func NewEventEntry(id EventID, priority EventPriority, readPriv Privilege, fabricSensitive bool) EventEntry {
	return EventEntry{
		ID:                id,
		Priority:          priority,
		ReadPrivilege:     readPriv,
		IsFabricSensitive: fabricSensitive,
	}
}
