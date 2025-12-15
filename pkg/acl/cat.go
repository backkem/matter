package acl

// CASE Authenticated Tag (CAT) handling.
// Spec: Section 2.5.5.5
//
// A CAT is a 32-bit value embedded in CASE certificates, encoded as:
//   - Upper 16 bits: Identifier (tag category)
//   - Lower 16 bits: Version (monotonically increasing)
//
// CATs are represented as NodeIDs in the range 0xFFFF_FFFD_xxxx_xxxx.
// The lower 32 bits of the NodeID contain the CAT value.

// CASEAuthTag is a 32-bit CASE Authenticated Tag.
// Format: [Identifier:16][Version:16]
type CASEAuthTag uint32

// CAT constants.
const (
	// CATUndefined represents an undefined/empty CAT slot.
	CATUndefined CASEAuthTag = 0

	// CATIdentifierMask extracts the identifier portion.
	CATIdentifierMask uint32 = 0xFFFF_0000

	// CATIdentifierShift is the bit position of the identifier.
	CATIdentifierShift = 16

	// CATVersionMask extracts the version portion.
	CATVersionMask uint32 = 0x0000_FFFF
)

// NodeID range constants for CAT-type NodeIDs.
// Spec: Section 2.5.5.1 (Node ID ranges)
const (
	// NodeIDMinCAT is the minimum CAT-type NodeID.
	NodeIDMinCAT uint64 = 0xFFFF_FFFD_0000_0000

	// NodeIDMaxCAT is the maximum CAT-type NodeID.
	NodeIDMaxCAT uint64 = 0xFFFF_FFFD_FFFF_FFFF

	// NodeIDCATMask extracts the CAT from a CAT-type NodeID.
	NodeIDCATMask uint64 = 0x0000_0000_FFFF_FFFF
)

// Special CAT identifiers.
const (
	// CATIdentifierAdmin is the Admin CAT identifier (0xFFFF).
	CATIdentifierAdmin uint16 = 0xFFFF

	// CATIdentifierAnchor is the Anchor CAT identifier (0xFFFE).
	CATIdentifierAnchor uint16 = 0xFFFE
)

// GetIdentifier returns the 16-bit identifier from a CAT.
func (c CASEAuthTag) GetIdentifier() uint16 {
	return uint16((uint32(c) & CATIdentifierMask) >> CATIdentifierShift)
}

// GetVersion returns the 16-bit version from a CAT.
func (c CASEAuthTag) GetVersion() uint16 {
	return uint16(uint32(c) & CATVersionMask)
}

// IsValid returns true if the CAT has a non-zero version.
// A version of 0 is invalid per spec.
func (c CASEAuthTag) IsValid() bool {
	return c.GetVersion() > 0
}

// NodeID returns this CAT encoded as a NodeID.
// The result is in the range 0xFFFF_FFFD_xxxx_xxxx.
func (c CASEAuthTag) NodeID() uint64 {
	return NodeIDMinCAT | uint64(c)
}

// NewCASEAuthTag creates a CAT from identifier and version.
func NewCASEAuthTag(identifier, version uint16) CASEAuthTag {
	return CASEAuthTag((uint32(identifier) << CATIdentifierShift) | uint32(version))
}

// CATFromNodeID extracts the CAT from a CAT-type NodeID.
// Returns CATUndefined if the NodeID is not a CAT-type.
func CATFromNodeID(nodeID uint64) CASEAuthTag {
	if !IsCATNodeID(nodeID) {
		return CATUndefined
	}
	return CASEAuthTag(nodeID & NodeIDCATMask)
}

// IsCATNodeID returns true if the NodeID represents a CAT.
// CAT NodeIDs are in the range 0xFFFF_FFFD_xxxx_xxxx.
func IsCATNodeID(nodeID uint64) bool {
	return nodeID >= NodeIDMinCAT && nodeID <= NodeIDMaxCAT
}

// CATValues holds up to 3 CASE Authenticated Tags from a certificate.
// Spec: CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES - 2 = 3
type CATValues [3]CASEAuthTag

// GetNumTagsPresent returns the count of non-undefined CATs.
func (c CATValues) GetNumTagsPresent() int {
	count := 0
	for _, cat := range c {
		if cat != CATUndefined {
			count++
		}
	}
	return count
}

// Contains returns true if the exact CAT value is in the set.
func (c CATValues) Contains(tag CASEAuthTag) bool {
	for _, cat := range c {
		if cat != CATUndefined && cat == tag {
			return true
		}
	}
	return false
}

// ContainsIdentifier returns true if any CAT with the given identifier is present.
func (c CATValues) ContainsIdentifier(identifier uint16) bool {
	for _, cat := range c {
		if cat != CATUndefined && cat.GetIdentifier() == identifier {
			return true
		}
	}
	return false
}

// AreValid returns true if all non-undefined CATs have valid versions
// and there are no duplicate identifiers.
func (c CATValues) AreValid() bool {
	for i, cat := range c {
		if cat == CATUndefined {
			continue
		}

		// Every non-empty entry must have version > 0
		if !cat.IsValid() {
			return false
		}

		// Check for duplicate identifiers
		identifier := cat.GetIdentifier()
		for j, other := range c {
			if i == j || other == CATUndefined {
				continue
			}
			if other.GetIdentifier() == identifier {
				return false // Duplicate identifier
			}
		}
	}
	return true
}

// CheckSubjectAgainstCATs implements CAT-based subject matching.
// Spec: Section 6.6.2.1.2
//
// Returns true if the subject (a CAT-type NodeID) matches any CAT in this set.
// A match occurs when:
//  1. Both are CATs (subject must be a CAT-type NodeID)
//  2. The identifiers match
//  3. The subject's version is > 0
//  4. This set's CAT version >= subject's CAT version
//
// This allows an ACL entry with CAT version N to match subjects with
// version N or any lower version (subjects retain access as they age).
func (c CATValues) CheckSubjectAgainstCATs(subject uint64) bool {
	if !IsCATNodeID(subject) {
		return false
	}

	subjectCAT := CATFromNodeID(subject)
	subjectIdentifier := subjectCAT.GetIdentifier()
	subjectVersion := subjectCAT.GetVersion()

	// Subject must have a valid version
	if subjectVersion == 0 {
		return false
	}

	for _, cat := range c {
		if cat == CATUndefined {
			continue
		}

		// Check identifier match
		if cat.GetIdentifier() != subjectIdentifier {
			continue
		}

		// Check version: our version must be >= subject's version
		// This means a CAT with version 8 matches entries requiring version 2, 3, ..., 8
		if cat.GetVersion() >= subjectVersion {
			return true
		}
	}

	return false
}

// Equal returns true if both CATValues contain the same set of CATs.
// Order does not matter, but the sets must be valid.
func (c CATValues) Equal(other CATValues) bool {
	if c.GetNumTagsPresent() != other.GetNumTagsPresent() {
		return false
	}

	if !c.AreValid() || !other.AreValid() {
		return false
	}

	for _, cat := range c {
		if cat == CATUndefined {
			continue
		}
		if !other.Contains(cat) {
			return false
		}
	}

	return true
}
