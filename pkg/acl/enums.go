package acl

// Privilege defines access privilege levels for ACL checks.
// Higher privileges subsume lower ones (Administer > Manage > Operate > View).
// Spec: Section 9.10.5.2 (AccessControlEntryPrivilegeEnum)
type Privilege uint8

const (
	// PrivilegeView allows read access to attributes and events.
	// Value 1 per spec.
	PrivilegeView Privilege = 1

	// PrivilegeProxyView allows proxy read access (deprecated, for compatibility).
	// Value 2 per spec.
	PrivilegeProxyView Privilege = 2

	// PrivilegeOperate allows View plus primary device function.
	// Implicitly grants View.
	// Value 3 per spec.
	PrivilegeOperate Privilege = 3

	// PrivilegeManage allows Operate plus persistent configuration changes.
	// Implicitly grants Operate and View.
	// Value 4 per spec.
	PrivilegeManage Privilege = 4

	// PrivilegeAdminister allows Manage plus Access Control cluster operations.
	// Implicitly grants all other privileges.
	// Value 5 per spec.
	PrivilegeAdminister Privilege = 5
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

// Grants returns true if this privilege level grants the requested privilege.
// Implements the privilege hierarchy from Spec 6.6.6.2.
//
// Hierarchy:
//   - Administer grants: Administer, Manage, Operate, View, ProxyView
//   - Manage grants: Manage, Operate, View
//   - Operate grants: Operate, View
//   - ProxyView grants: ProxyView, View
//   - View grants: View only
func (p Privilege) Grants(requested Privilege) bool {
	switch p {
	case PrivilegeView:
		return requested == PrivilegeView
	case PrivilegeProxyView:
		return requested == PrivilegeProxyView || requested == PrivilegeView
	case PrivilegeOperate:
		return requested == PrivilegeOperate || requested == PrivilegeView
	case PrivilegeManage:
		return requested == PrivilegeManage || requested == PrivilegeOperate || requested == PrivilegeView
	case PrivilegeAdminister:
		return requested == PrivilegeAdminister || requested == PrivilegeManage ||
			requested == PrivilegeOperate || requested == PrivilegeView || requested == PrivilegeProxyView
	default:
		return false
	}
}

// AuthMode identifies the authentication mode for a session.
// Spec: Section 9.10.5.4 (AccessControlEntryAuthModeEnum)
type AuthMode uint8

const (
	// AuthModeUnknown indicates an uninitialized or invalid mode.
	AuthModeUnknown AuthMode = 0

	// AuthModePASE indicates Passcode Authenticated Session Establishment.
	// Value 1 per spec.
	AuthModePASE AuthMode = 1

	// AuthModeCASE indicates Certificate Authenticated Session Establishment.
	// Value 2 per spec.
	AuthModeCASE AuthMode = 2

	// AuthModeGroup indicates group authentication (multicast).
	// Value 3 per spec.
	AuthModeGroup AuthMode = 3
)

// String returns a human-readable name for the authentication mode.
func (m AuthMode) String() string {
	switch m {
	case AuthModePASE:
		return "PASE"
	case AuthModeCASE:
		return "CASE"
	case AuthModeGroup:
		return "Group"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the auth mode is a defined value (excluding Unknown).
func (m AuthMode) IsValid() bool {
	return m >= AuthModePASE && m <= AuthModeGroup
}

// RequestType identifies the type of Interaction Model operation.
// Used to determine which privilege is required.
type RequestType uint8

const (
	// RequestTypeUnknown indicates an uninitialized request type.
	RequestTypeUnknown RequestType = iota

	// RequestTypeAttributeRead is for reading attribute values.
	RequestTypeAttributeRead

	// RequestTypeAttributeWrite is for writing attribute values.
	RequestTypeAttributeWrite

	// RequestTypeCommandInvoke is for invoking commands.
	RequestTypeCommandInvoke

	// RequestTypeEventRead is for reading events.
	RequestTypeEventRead
)

// String returns a human-readable name for the request type.
func (r RequestType) String() string {
	switch r {
	case RequestTypeAttributeRead:
		return "AttributeRead"
	case RequestTypeAttributeWrite:
		return "AttributeWrite"
	case RequestTypeCommandInvoke:
		return "CommandInvoke"
	case RequestTypeEventRead:
		return "EventRead"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the request type is a defined value (excluding Unknown).
func (r RequestType) IsValid() bool {
	return r >= RequestTypeAttributeRead && r <= RequestTypeEventRead
}

// Result represents the outcome of an access control check.
type Result uint8

const (
	// ResultDenied indicates access was denied (no matching ACL entry).
	ResultDenied Result = iota

	// ResultAllowed indicates access was granted by an ACL entry.
	ResultAllowed

	// ResultRestricted indicates access was denied by an Access Restriction List entry.
	// This is a stronger denial than ResultDenied.
	ResultRestricted
)

// String returns a human-readable name for the result.
func (r Result) String() string {
	switch r {
	case ResultDenied:
		return "Denied"
	case ResultAllowed:
		return "Allowed"
	case ResultRestricted:
		return "Restricted"
	default:
		return "Unknown"
	}
}
