package datamodel

// Global attribute IDs are mandatory attributes present on every cluster instance.
// Spec: Section 7.13, Table 93
const (
	// GlobalAttrClusterRevision (0xFFFD) indicates the cluster revision.
	// Spec: Section 7.13.1
	GlobalAttrClusterRevision AttributeID = 0xFFFD

	// GlobalAttrFeatureMap (0xFFFC) indicates supported optional features.
	// Spec: Section 7.13.2
	GlobalAttrFeatureMap AttributeID = 0xFFFC

	// GlobalAttrAttributeList (0xFFFB) lists all supported attribute IDs.
	// Spec: Section 7.13.3
	GlobalAttrAttributeList AttributeID = 0xFFFB

	// GlobalAttrEventList (0xFFFA) lists all supported event IDs.
	// Deprecated in Matter 1.5
	GlobalAttrEventList AttributeID = 0xFFFA

	// GlobalAttrAcceptedCommandList (0xFFF9) lists accepted command IDs.
	// Spec: Section 7.13.4
	GlobalAttrAcceptedCommandList AttributeID = 0xFFF9

	// GlobalAttrGeneratedCommandList (0xFFF8) lists generated command IDs.
	// Spec: Section 7.13.5
	GlobalAttrGeneratedCommandList AttributeID = 0xFFF8
)

// Global command IDs are commands that may be present on any cluster
// supporting atomic writes.
// Spec: Section 7.13, Table 95
const (
	// GlobalCmdAtomicRequest (0xFE) begins, commits or rolls back atomic writes.
	// Spec: Section 7.13.7
	GlobalCmdAtomicRequest CommandID = 0xFE

	// GlobalCmdAtomicResponse (0xFD) is returned in response to AtomicRequest.
	// Spec: Section 7.13.8
	GlobalCmdAtomicResponse CommandID = 0xFD
)

// Global field IDs are fields present in specific contexts.
// Spec: Section 7.13, Table 94
const (
	// GlobalFieldFabricIndex (0xFE) is present in fabric-scoped data.
	// Spec: Section 7.13.6
	GlobalFieldFabricIndex = 0xFE
)

// IsGlobalAttribute returns true if the attribute ID is a global attribute.
func IsGlobalAttribute(id AttributeID) bool {
	return id >= GlobalAttrGeneratedCommandList && id <= GlobalAttrClusterRevision
}

// IsGlobalCommand returns true if the command ID is a global command.
func IsGlobalCommand(id CommandID) bool {
	return id == GlobalCmdAtomicRequest || id == GlobalCmdAtomicResponse
}

// GlobalAttributeEntries returns the standard global attribute entries.
// These must be present on every cluster instance.
func GlobalAttributeEntries() []AttributeEntry {
	viewPriv := PrivilegeView
	return []AttributeEntry{
		{
			ID:            GlobalAttrClusterRevision,
			Quality:       AttrQualityFixed,
			ReadPrivilege: &viewPriv,
		},
		{
			ID:            GlobalAttrFeatureMap,
			Quality:       AttrQualityFixed,
			ReadPrivilege: &viewPriv,
		},
		{
			ID:            GlobalAttrAttributeList,
			Quality:       AttrQualityFixed | AttrQualityList,
			ReadPrivilege: &viewPriv,
		},
		{
			ID:            GlobalAttrAcceptedCommandList,
			Quality:       AttrQualityFixed | AttrQualityList,
			ReadPrivilege: &viewPriv,
		},
		{
			ID:            GlobalAttrGeneratedCommandList,
			Quality:       AttrQualityFixed | AttrQualityList,
			ReadPrivilege: &viewPriv,
		},
	}
}

// Well-known endpoint IDs
const (
	// EndpointRoot is the root endpoint (always 0).
	EndpointRoot EndpointID = 0
)

// Well-known cluster IDs (utility clusters commonly used)
const (
	// ClusterDescriptor is the Descriptor cluster ID.
	ClusterDescriptor ClusterID = 0x001D

	// ClusterBinding is the Binding cluster ID.
	ClusterBinding ClusterID = 0x001E

	// ClusterAccessControl is the Access Control cluster ID.
	ClusterAccessControl ClusterID = 0x001F

	// ClusterBasicInformation is the Basic Information cluster ID.
	ClusterBasicInformation ClusterID = 0x0028

	// ClusterOTASoftwareUpdateProvider is the OTA Provider cluster ID.
	ClusterOTASoftwareUpdateProvider ClusterID = 0x0029

	// ClusterOTASoftwareUpdateRequestor is the OTA Requestor cluster ID.
	ClusterOTASoftwareUpdateRequestor ClusterID = 0x002A

	// ClusterGeneralCommissioning is the General Commissioning cluster ID.
	ClusterGeneralCommissioning ClusterID = 0x0030

	// ClusterNetworkCommissioning is the Network Commissioning cluster ID.
	ClusterNetworkCommissioning ClusterID = 0x0031

	// ClusterGeneralDiagnostics is the General Diagnostics cluster ID.
	ClusterGeneralDiagnostics ClusterID = 0x0033

	// ClusterSoftwareDiagnostics is the Software Diagnostics cluster ID.
	ClusterSoftwareDiagnostics ClusterID = 0x0034

	// ClusterAdministratorCommissioning is the Admin Commissioning cluster ID.
	ClusterAdministratorCommissioning ClusterID = 0x003C

	// ClusterOperationalCredentials is the Operational Credentials cluster ID.
	ClusterOperationalCredentials ClusterID = 0x003E

	// ClusterGroupKeyManagement is the Group Key Management cluster ID.
	ClusterGroupKeyManagement ClusterID = 0x003F
)

// Well-known application cluster IDs
const (
	// ClusterIdentify is the Identify cluster ID.
	ClusterIdentify ClusterID = 0x0003

	// ClusterGroups is the Groups cluster ID.
	ClusterGroups ClusterID = 0x0004

	// ClusterOnOff is the On/Off cluster ID.
	ClusterOnOff ClusterID = 0x0006

	// ClusterLevelControl is the Level Control cluster ID.
	ClusterLevelControl ClusterID = 0x0008

	// ClusterColorControl is the Color Control cluster ID.
	ClusterColorControl ClusterID = 0x0300
)

// Well-known device type IDs
const (
	// DeviceTypeRootNode is the Root Node device type.
	DeviceTypeRootNode DeviceTypeID = 0x0016

	// DeviceTypePowerSource is the Power Source device type.
	DeviceTypePowerSource DeviceTypeID = 0x0011

	// DeviceTypeOnOffLight is the On/Off Light device type.
	DeviceTypeOnOffLight DeviceTypeID = 0x0100

	// DeviceTypeDimmableLight is the Dimmable Light device type.
	DeviceTypeDimmableLight DeviceTypeID = 0x0101

	// DeviceTypeColorTemperatureLight is the Color Temperature Light device type.
	DeviceTypeColorTemperatureLight DeviceTypeID = 0x010C

	// DeviceTypeExtendedColorLight is the Extended Color Light device type.
	DeviceTypeExtendedColorLight DeviceTypeID = 0x010D

	// DeviceTypeOnOffLightSwitch is the On/Off Light Switch device type.
	DeviceTypeOnOffLightSwitch DeviceTypeID = 0x0103

	// DeviceTypeDimmerSwitch is the Dimmer Switch device type.
	DeviceTypeDimmerSwitch DeviceTypeID = 0x0104

	// DeviceTypeColorDimmerSwitch is the Color Dimmer Switch device type.
	DeviceTypeColorDimmerSwitch DeviceTypeID = 0x0105

	// DeviceTypeContactSensor is the Contact Sensor device type.
	DeviceTypeContactSensor DeviceTypeID = 0x0015

	// DeviceTypeTemperatureSensor is the Temperature Sensor device type.
	DeviceTypeTemperatureSensor DeviceTypeID = 0x0302

	// DeviceTypeOccupancySensor is the Occupancy Sensor device type.
	DeviceTypeOccupancySensor DeviceTypeID = 0x0107
)
