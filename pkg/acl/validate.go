package acl

import "errors"

// Validation errors.
var (
	ErrInvalidFabricIndex    = errors.New("acl: invalid fabric index")
	ErrInvalidAuthMode       = errors.New("acl: invalid auth mode")
	ErrInvalidPrivilege      = errors.New("acl: invalid privilege")
	ErrGroupAdminister       = errors.New("acl: group auth mode cannot have administer privilege")
	ErrInvalidSubject        = errors.New("acl: invalid subject for auth mode")
	ErrEmptySubjectsPASE     = errors.New("acl: PASE auth mode must have subjects")
	ErrInvalidTarget         = errors.New("acl: invalid target")
	ErrTargetEmpty           = errors.New("acl: target must have at least one field set")
	ErrTargetEndpointAndType = errors.New("acl: target cannot have both endpoint and device type")
	ErrInvalidClusterID      = errors.New("acl: invalid cluster ID")
	ErrInvalidEndpointID     = errors.New("acl: invalid endpoint ID")
	ErrInvalidDeviceTypeID   = errors.New("acl: invalid device type ID")
)

// Cluster ID validity ranges (Spec 7.10.2).
const (
	// Standard cluster range
	ClusterIDStdMin uint32 = 0x0000_0000
	ClusterIDStdMax uint32 = 0x0000_7FFF

	// Manufacturer-specific cluster range (per vendor)
	ClusterIDMfgMin uint32 = 0x0000_FC00
	ClusterIDMfgMax uint32 = 0x0000_FFFE

	// Wildcard (invalid for ACL entry)
	ClusterIDWildcard uint32 = 0xFFFF_FFFF
)

// Endpoint ID validity (Spec 7.9.1).
const (
	EndpointIDMin     uint16 = 0x0000
	EndpointIDMax     uint16 = 0xFFFE
	EndpointIDInvalid uint16 = 0xFFFF
)

// Device Type ID validity (Spec 7.10.7).
const (
	DeviceTypeIDMin      uint32 = 0x0000_0000
	DeviceTypeIDMax      uint32 = 0x0000_BFFF
	DeviceTypeIDWildcard uint32 = 0x0000_FFFF
)

// ValidateEntry checks if an ACL entry is valid per spec rules.
// Returns nil if valid, or an error describing the validation failure.
//
// Validation rules from Spec 9.10.5.6 and C++ AccessControl::IsValid():
//   - FabricIndex must be valid (1-254)
//   - AuthMode must be CASE or Group (PASE not stored in ACL)
//   - Group auth mode cannot have Administer privilege
//   - Subjects must be valid for their auth mode
//   - PASE would need subjects (but PASE entries aren't stored)
//   - Targets must be valid
func ValidateEntry(entry *Entry) error {
	// Validate fabric index
	if !entry.FabricIndex.IsValid() {
		return ErrInvalidFabricIndex
	}

	// Validate auth mode (only CASE and Group are stored in ACL)
	if entry.AuthMode != AuthModeCASE && entry.AuthMode != AuthModeGroup {
		return ErrInvalidAuthMode
	}

	// Validate privilege
	if !entry.Privilege.IsValid() {
		return ErrInvalidPrivilege
	}

	// Group auth mode cannot have Administer privilege
	if entry.AuthMode == AuthModeGroup && entry.Privilege == PrivilegeAdminister {
		return ErrGroupAdminister
	}

	// Validate subjects for auth mode
	for _, subject := range entry.Subjects {
		if err := ValidateSubject(entry.AuthMode, subject); err != nil {
			return err
		}
	}

	// Validate targets
	for _, target := range entry.Targets {
		if err := ValidateTarget(&target); err != nil {
			return err
		}
	}

	return nil
}

// ValidateSubject checks if a subject is valid for the given auth mode.
func ValidateSubject(authMode AuthMode, subject uint64) error {
	switch authMode {
	case AuthModeCASE:
		// CASE subjects must be operational NodeIDs or valid CAT NodeIDs
		if IsOperationalNodeID(subject) {
			return nil
		}
		if IsCATNodeID(subject) {
			cat := CATFromNodeID(subject)
			if cat.IsValid() {
				return nil
			}
		}
		return ErrInvalidSubject

	case AuthModeGroup:
		// Group subjects must be group NodeIDs
		if !IsGroupNodeID(subject) {
			return ErrInvalidSubject
		}
		// Group ID must be valid (1-0xFFFF)
		groupID := GroupIDFromNodeID(subject)
		if !IsValidGroupID(groupID) {
			return ErrInvalidSubject
		}
		return nil

	case AuthModePASE:
		// PASE subjects must be PAKE NodeIDs
		if !IsPAKENodeID(subject) {
			return ErrInvalidSubject
		}
		return nil

	default:
		return ErrInvalidAuthMode
	}
}

// ValidateTarget checks if a target is valid for ACL entries.
func ValidateTarget(target *Target) error {
	// Target must have at least one field set
	if target.IsEmpty() {
		return ErrTargetEmpty
	}

	// Cannot have both Endpoint and DeviceType
	if target.Endpoint != nil && target.DeviceType != nil {
		return ErrTargetEndpointAndType
	}

	// Validate cluster ID if present
	if target.Cluster != nil {
		if !IsValidClusterID(*target.Cluster) {
			return ErrInvalidClusterID
		}
	}

	// Validate endpoint ID if present
	if target.Endpoint != nil {
		if !IsValidEndpointID(*target.Endpoint) {
			return ErrInvalidEndpointID
		}
	}

	// Validate device type ID if present
	if target.DeviceType != nil {
		if !IsValidDeviceTypeID(*target.DeviceType) {
			return ErrInvalidDeviceTypeID
		}
	}

	return nil
}

// IsValidClusterID checks if a cluster ID is valid for ACL targets.
// Valid clusters are in standard or manufacturer-specific ranges.
// Wildcards (0xFFFF_FFFF) are not valid in ACL entries.
func IsValidClusterID(id uint32) bool {
	// Check standard range (0x0000 - 0x7FFF)
	if id <= ClusterIDStdMax {
		return true
	}

	// Check manufacturer-specific range for any vendor prefix
	// Format: 0xXXXX_FC00 - 0xXXXX_FFFE where XXXX is vendor ID
	suffix := id & 0x0000_FFFF
	if suffix >= 0xFC00 && suffix <= 0xFFFE {
		// Vendor prefix must be valid (not all 0xFFFF which would be wildcard territory)
		prefix := id >> 16
		if prefix <= 0xFFF4 {
			return true
		}
	}

	return false
}

// IsValidEndpointID checks if an endpoint ID is valid for ACL targets.
// Valid endpoints are 0x0000 - 0xFFFE.
// The wildcard endpoint (0xFFFF) is not valid in ACL entries.
func IsValidEndpointID(id uint16) bool {
	return id != EndpointIDInvalid
}

// IsValidDeviceTypeID checks if a device type ID is valid for ACL targets.
// Valid device types are 0x0000_0000 - 0x0000_BFFF per vendor prefix.
func IsValidDeviceTypeID(id uint32) bool {
	// Check the suffix (lower 16 bits) is in valid range
	suffix := id & 0x0000_FFFF
	if suffix > DeviceTypeIDMax {
		return false
	}

	// Wildcard is not valid
	if suffix == DeviceTypeIDWildcard {
		return false
	}

	return true
}
