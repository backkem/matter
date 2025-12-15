// Package discovery implements DNS-SD (mDNS) discovery for Matter nodes.
//
// This package provides:
//   - Service advertising for commissionable, operational, and commissioner nodes
//   - Service resolution to discover other Matter nodes on the network
//   - TXT record encoding/decoding for Matter-specific attributes
//
// Spec References:
//   - Section 4.3: Discovery
//   - Section 4.3.1: Commissionable Node Discovery (_matterc._udp)
//   - Section 4.3.2: Operational Discovery (_matter._tcp)
//   - Section 4.3.3: Commissioner Discovery (_matterd._udp)
package discovery

// ServiceType identifies the type of DNS-SD service.
// Spec Section 4.3
type ServiceType int

// ServiceType constants.
const (
	// ServiceTypeUnknown represents an unknown or invalid service type.
	ServiceTypeUnknown ServiceType = iota

	// ServiceTypeCommissionable is for nodes ready to be commissioned.
	// Service type: _matterc._udp
	// Spec Section 4.3.1
	ServiceTypeCommissionable

	// ServiceTypeOperational is for commissioned nodes in normal operation.
	// Service type: _matter._tcp
	// Spec Section 4.3.2
	ServiceTypeOperational

	// ServiceTypeCommissioner is for commissioners advertising their presence.
	// Service type: _matterd._udp
	// Spec Section 4.3.3
	ServiceTypeCommissioner
)

// DNS-SD service type strings.
const (
	// ServiceCommissionable is the DNS-SD service type for commissionable nodes.
	ServiceCommissionable = "_matterc._udp"

	// ServiceOperational is the DNS-SD service type for operational nodes.
	ServiceOperational = "_matter._tcp"

	// ServiceCommissioner is the DNS-SD service type for commissioners.
	ServiceCommissioner = "_matterd._udp"

	// DefaultDomain is the default mDNS domain.
	DefaultDomain = "local."
)

// String returns a human-readable string for the service type.
func (s ServiceType) String() string {
	switch s {
	case ServiceTypeCommissionable:
		return "Commissionable"
	case ServiceTypeOperational:
		return "Operational"
	case ServiceTypeCommissioner:
		return "Commissioner"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the service type is valid.
func (s ServiceType) IsValid() bool {
	return s == ServiceTypeCommissionable ||
		s == ServiceTypeOperational ||
		s == ServiceTypeCommissioner
}

// ServiceString returns the DNS-SD service type string.
func (s ServiceType) ServiceString() string {
	switch s {
	case ServiceTypeCommissionable:
		return ServiceCommissionable
	case ServiceTypeOperational:
		return ServiceOperational
	case ServiceTypeCommissioner:
		return ServiceCommissioner
	default:
		return ""
	}
}

// CommissioningMode indicates the commissioning state of a node.
// Spec Section 4.3.1.3
type CommissioningMode int

// CommissioningMode constants.
const (
	// CommissioningModeDisabled indicates the node is not currently in commissioning mode.
	// CM=0: Extended Discovery only, not accepting commissioning.
	CommissioningModeDisabled CommissioningMode = 0

	// CommissioningModeBasic indicates basic commissioning mode.
	// CM=1: Node is in commissioning mode (e.g., factory reset, first boot).
	CommissioningModeBasic CommissioningMode = 1

	// CommissioningModeEnhanced indicates enhanced commissioning mode.
	// CM=2: Administrator-opened commissioning window (OpenCommissioningWindow command).
	CommissioningModeEnhanced CommissioningMode = 2
)

// String returns a human-readable string for the commissioning mode.
func (c CommissioningMode) String() string {
	switch c {
	case CommissioningModeDisabled:
		return "Disabled"
	case CommissioningModeBasic:
		return "Basic"
	case CommissioningModeEnhanced:
		return "Enhanced"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the commissioning mode is valid.
func (c CommissioningMode) IsValid() bool {
	return c >= CommissioningModeDisabled && c <= CommissioningModeEnhanced
}

// ICDMode indicates the operating mode of an Intermittently Connected Device.
// Spec Section 4.3.4
type ICDMode int

// ICDMode constants.
const (
	// ICDModeSIT indicates Short Idle Time operating mode.
	// ICD=0: Device operates in Short Idle Time mode.
	ICDModeSIT ICDMode = 0

	// ICDModeLIT indicates Long Idle Time operating mode.
	// ICD=1: Device operates in Long Idle Time mode.
	ICDModeLIT ICDMode = 1
)

// String returns a human-readable string for the ICD mode.
func (i ICDMode) String() string {
	switch i {
	case ICDModeSIT:
		return "SIT"
	case ICDModeLIT:
		return "LIT"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the ICD mode is valid.
func (i ICDMode) IsValid() bool {
	return i == ICDModeSIT || i == ICDModeLIT
}
