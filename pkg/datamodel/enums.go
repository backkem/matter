// Package datamodel provides the foundational interfaces and types for the
// Matter Data Model (Spec Chapter 7).
//
// This package defines the hierarchy of Node → Endpoint → Cluster and the
// interfaces for reading/writing attributes, invoking commands, and handling
// events. It sits between the Interaction Model (pkg/im) and cluster
// implementations (pkg/clusters/*).
//
// Spec References:
//   - Section 7.4: Element hierarchy
//   - Section 7.8: Node
//   - Section 7.9: Endpoint
//   - Section 7.10: Cluster
//   - Section 7.11: Command
//   - Section 7.12: Attribute
//   - Section 7.13: Global Elements
//   - Section 7.14: Event
package datamodel

// Privilege defines access privilege levels for ACL checks.
// Spec: Section 7.6
type Privilege int

const (
	// PrivilegeUnknown indicates an uninitialized or invalid privilege.
	PrivilegeUnknown Privilege = iota

	// PrivilegeView allows read access to attributes and events.
	// Spec: Section 7.6.6
	PrivilegeView

	// PrivilegeProxyView allows proxy read access (for proxy devices).
	PrivilegeProxyView

	// PrivilegeOperate allows read/write/invoke access for normal operations.
	// Spec: Section 7.6.7
	PrivilegeOperate

	// PrivilegeManage allows configuration and management operations.
	// Spec: Section 7.6.8
	PrivilegeManage

	// PrivilegeAdminister allows full administrative control.
	// Spec: Section 7.6.9
	PrivilegeAdminister
)

// String returns a human-readable name for the privilege level.
func (p Privilege) String() string {
	switch p {
	case PrivilegeView:
		return "View"
	case PrivilegeProxyView:
		return "ProxyView"
	case PrivilegeOperate:
		return "Operate"
	case PrivilegeManage:
		return "Manage"
	case PrivilegeAdminister:
		return "Administer"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the privilege is a defined value.
func (p Privilege) IsValid() bool {
	return p >= PrivilegeView && p <= PrivilegeAdminister
}

// AttributeQuality defines quality flags for attributes.
// These flags indicate various properties of an attribute.
// Spec: Section 7.7, 7.12
type AttributeQuality uint32

const (
	// AttrQualityChangesOmitted indicates fast-changing data that won't be
	// reported in subscriptions (C quality).
	// Spec: Section 7.7.1
	AttrQualityChangesOmitted AttributeQuality = 1 << iota

	// AttrQualityFixed indicates read-only data that rarely changes (F quality).
	// Spec: Section 7.7.2
	AttrQualityFixed

	// AttrQualitySingleton indicates a cluster that is singleton on the node (I quality).
	// Spec: Section 7.7.3
	AttrQualitySingleton

	// AttrQualityDiagnostics indicates verbose diagnostics cluster data (K quality).
	// Spec: Section 7.7.4
	AttrQualityDiagnostics

	// AttrQualityNonVolatile indicates persistent data across restarts (N quality).
	// Spec: Section 7.7.6
	AttrQualityNonVolatile

	// AttrQualityReportable indicates the attribute supports reporting (P quality).
	// Spec: Section 7.7.7
	AttrQualityReportable

	// AttrQualityQuieter indicates data with fluctuating rate where some changes
	// are meaningless to report (Q quality).
	// Spec: Section 7.7.8
	AttrQualityQuieter

	// AttrQualityScene indicates the attribute is part of a scene (S quality).
	// Spec: Section 7.7.9
	AttrQualityScene

	// AttrQualityAtomic indicates the attribute requires atomic writes (T quality).
	// Spec: Section 7.7.11
	AttrQualityAtomic

	// AttrQualityNullable indicates the data type is nullable (X quality).
	// Spec: Section 7.7.10
	AttrQualityNullable

	// AttrQualityList indicates this attribute is a list type.
	AttrQualityList

	// AttrQualityFabricScoped indicates fabric-scoped access (F access modifier).
	// Spec: Section 7.6.4
	AttrQualityFabricScoped

	// AttrQualityFabricSensitive indicates fabric-sensitive access (S access modifier).
	// Spec: Section 7.6.5
	AttrQualityFabricSensitive

	// AttrQualityTimed indicates timed interaction required for writes (T access modifier).
	// Spec: Section 7.6.10
	AttrQualityTimed
)

// String returns a human-readable representation of the quality flags.
func (q AttributeQuality) String() string {
	if q == 0 {
		return "None"
	}

	var result string
	if q&AttrQualityChangesOmitted != 0 {
		result += "C"
	}
	if q&AttrQualityFixed != 0 {
		result += "F"
	}
	if q&AttrQualitySingleton != 0 {
		result += "I"
	}
	if q&AttrQualityDiagnostics != 0 {
		result += "K"
	}
	if q&AttrQualityNonVolatile != 0 {
		result += "N"
	}
	if q&AttrQualityReportable != 0 {
		result += "P"
	}
	if q&AttrQualityQuieter != 0 {
		result += "Q"
	}
	if q&AttrQualityScene != 0 {
		result += "S"
	}
	if q&AttrQualityAtomic != 0 {
		result += "T"
	}
	if q&AttrQualityNullable != 0 {
		result += "X"
	}
	if q&AttrQualityList != 0 {
		result += "[List]"
	}
	if q&AttrQualityFabricScoped != 0 {
		result += "[FabricScoped]"
	}
	if q&AttrQualityFabricSensitive != 0 {
		result += "[FabricSensitive]"
	}
	if q&AttrQualityTimed != 0 {
		result += "[Timed]"
	}

	if result == "" {
		return "None"
	}
	return result
}

// CommandQuality defines quality flags for commands.
// Spec: Section 7.11
type CommandQuality uint32

const (
	// CmdQualityFabricScoped indicates the command requires fabric context (F quality).
	CmdQualityFabricScoped CommandQuality = 1 << iota

	// CmdQualityTimed indicates the command requires timed interaction (T quality).
	CmdQualityTimed

	// CmdQualityLargeMessage indicates the command may exceed minimum MTU (L quality).
	// Spec: Section 7.7.5
	CmdQualityLargeMessage
)

// String returns a human-readable representation of the command quality flags.
func (q CommandQuality) String() string {
	if q == 0 {
		return "None"
	}

	var result string
	if q&CmdQualityFabricScoped != 0 {
		result += "F"
	}
	if q&CmdQualityTimed != 0 {
		result += "T"
	}
	if q&CmdQualityLargeMessage != 0 {
		result += "L"
	}

	if result == "" {
		return "None"
	}
	return result
}

// EventPriority defines the priority level for events.
// Spec: Section 7.14.1.3
type EventPriority int

const (
	// EventPriorityDebug is for debugging information.
	EventPriorityDebug EventPriority = iota

	// EventPriorityInfo is for informational events.
	EventPriorityInfo

	// EventPriorityCritical is for critical events that must not be lost.
	EventPriorityCritical
)

// String returns a human-readable name for the event priority.
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

// IsValid returns true if the priority is a defined value.
func (p EventPriority) IsValid() bool {
	return p >= EventPriorityDebug && p <= EventPriorityCritical
}

// ClusterClassification identifies the type of cluster.
// Spec: Section 7.10.8
type ClusterClassification int

const (
	// ClusterClassUnknown indicates an uninitialized classification.
	ClusterClassUnknown ClusterClassification = iota

	// ClusterClassUtility indicates a utility cluster (not primary operation).
	// Spec: Section 7.10.8.1
	ClusterClassUtility

	// ClusterClassApplication indicates an application cluster (primary operation).
	// Spec: Section 7.10.8.2
	ClusterClassApplication
)

// String returns a human-readable name for the cluster classification.
func (c ClusterClassification) String() string {
	switch c {
	case ClusterClassUtility:
		return "Utility"
	case ClusterClassApplication:
		return "Application"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the classification is a defined value.
func (c ClusterClassification) IsValid() bool {
	return c == ClusterClassUtility || c == ClusterClassApplication
}

// EndpointComposition defines endpoint composition patterns.
// Spec: Section 9.2.1
type EndpointComposition int

const (
	// CompositionUnknown indicates an uninitialized composition pattern.
	CompositionUnknown EndpointComposition = iota

	// CompositionTree supports a general tree of endpoints.
	// Used for physical device composition (e.g., Refrigerator).
	CompositionTree

	// CompositionFullFamily is a flat list of all descendant endpoints.
	// Used by Root Node and Aggregator device types.
	CompositionFullFamily
)

// String returns a human-readable name for the composition pattern.
func (c EndpointComposition) String() string {
	switch c {
	case CompositionTree:
		return "Tree"
	case CompositionFullFamily:
		return "FullFamily"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the composition is a defined value.
func (c EndpointComposition) IsValid() bool {
	return c == CompositionTree || c == CompositionFullFamily
}

// AuthMode identifies the authentication mode for a session.
type AuthMode int

const (
	// AuthModeUnknown indicates an uninitialized or invalid mode.
	AuthModeUnknown AuthMode = iota

	// AuthModeCASE indicates Certificate Authenticated Session Establishment.
	AuthModeCASE

	// AuthModePASE indicates Passcode Authenticated Session Establishment.
	AuthModePASE

	// AuthModeGroup indicates group authentication.
	AuthModeGroup
)

// String returns a human-readable name for the authentication mode.
func (m AuthMode) String() string {
	switch m {
	case AuthModeCASE:
		return "CASE"
	case AuthModePASE:
		return "PASE"
	case AuthModeGroup:
		return "Group"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the auth mode is a defined value.
func (m AuthMode) IsValid() bool {
	return m >= AuthModeCASE && m <= AuthModeGroup
}
