// Package fabric manages the Fabric Table for Matter nodes.
//
// A fabric is a security domain defined by a Root CA certificate and a 64-bit
// Fabric ID. Each node can be commissioned into multiple fabrics, with each
// fabric entry tracked by a local 8-bit Fabric Index.
//
// This package provides:
//   - Core types: FabricIndex, FabricID, NodeID, VendorID
//   - Compressed Fabric ID computation (for DNS-SD discovery)
//   - FabricInfo storage structure
//   - FabricTable manager with thread-safe CRUD operations
//
// Spec References:
//   - Section 2.5.1: Fabric References and Fabric Identifier
//   - Section 4.3.2.2: Compressed Fabric Identifier
//   - Section 7.5.2: Fabric-Index
//   - Section 11.18: Operational Credentials Cluster
package fabric

import "fmt"

// FabricIndex is an 8-bit local index identifying a fabric on this node.
// Valid values are 1-254. The value 0 is invalid/unassigned.
// Spec Section 7.5.2
type FabricIndex uint8

// FabricIndex constants.
const (
	// FabricIndexMin is the minimum valid fabric index.
	FabricIndexMin FabricIndex = 1
	// FabricIndexMax is the maximum valid fabric index.
	FabricIndexMax FabricIndex = 254
	// FabricIndexInvalid represents an invalid/unassigned fabric index.
	FabricIndexInvalid FabricIndex = 0
)

// IsValid returns true if the fabric index is in the valid range [1, 254].
func (f FabricIndex) IsValid() bool {
	return f >= FabricIndexMin && f <= FabricIndexMax
}

// String returns a string representation of the fabric index.
func (f FabricIndex) String() string {
	if f == FabricIndexInvalid {
		return "FabricIndex(invalid)"
	}
	return fmt.Sprintf("FabricIndex(%d)", f)
}

// FabricID is a 64-bit fabric identifier.
// The value 0 is reserved and invalid.
// Spec Section 2.5.1
type FabricID uint64

// FabricIDInvalid is the reserved invalid fabric ID value.
const FabricIDInvalid FabricID = 0

// IsValid returns true if the fabric ID is valid (non-zero).
func (f FabricID) IsValid() bool {
	return f != FabricIDInvalid
}

// String returns a string representation of the fabric ID.
func (f FabricID) String() string {
	return fmt.Sprintf("FabricID(0x%016X)", uint64(f))
}

// NodeID is a 64-bit node identifier.
// Operational Node IDs are in the range [0x0000_0000_0000_0001, 0xFFFF_FFFE_FFFF_FFFD].
// Spec Section 2.5.5.1
type NodeID uint64

// NodeID range constants for operational nodes.
const (
	// NodeIDMinOperational is the minimum valid operational node ID.
	NodeIDMinOperational NodeID = 0x0000_0000_0000_0001
	// NodeIDMaxOperational is the maximum valid operational node ID.
	NodeIDMaxOperational NodeID = 0xFFFF_FFFE_FFFF_FFFD
)

// Special Node ID values.
const (
	// NodeIDUnspecified represents an unspecified/invalid node ID.
	NodeIDUnspecified NodeID = 0x0000_0000_0000_0000
)

// IsOperational returns true if the node ID is a valid operational node ID.
func (n NodeID) IsOperational() bool {
	return n >= NodeIDMinOperational && n <= NodeIDMaxOperational
}

// String returns a string representation of the node ID.
func (n NodeID) String() string {
	return fmt.Sprintf("NodeID(0x%016X)", uint64(n))
}

// VendorID is a 16-bit vendor identifier.
// Spec Section 2.5.3
type VendorID uint16

// VendorID constants.
const (
	// VendorIDUnspecified represents an unspecified vendor ID.
	VendorIDUnspecified VendorID = 0
	// VendorIDTestVendor1 is a test vendor ID for development.
	VendorIDTestVendor1 VendorID = 0xFFF1
	// VendorIDTestVendor2 is a test vendor ID for development.
	VendorIDTestVendor2 VendorID = 0xFFF2
	// VendorIDTestVendor3 is a test vendor ID for development.
	VendorIDTestVendor3 VendorID = 0xFFF3
	// VendorIDTestVendor4 is a test vendor ID for development.
	VendorIDTestVendor4 VendorID = 0xFFF4
)

// String returns a string representation of the vendor ID.
func (v VendorID) String() string {
	return fmt.Sprintf("VendorID(0x%04X)", uint16(v))
}

// Compressed Fabric ID size.
const (
	// CompressedFabricIDSize is the size of the compressed fabric ID in bytes.
	CompressedFabricIDSize = 8
)

// Certificate size limits from spec Section 6.1.3.
const (
	// MaxCertSize is the maximum Matter TLV certificate size (400 bytes).
	MaxCertSize = 400
	// RootPublicKeySize is the uncompressed P-256 public key size (65 bytes).
	RootPublicKeySize = 65
	// IPKSize is the Identity Protection Key size (16 bytes).
	IPKSize = 16
	// MaxLabelSize is the maximum fabric label size (32 bytes).
	MaxLabelSize = 32
)

// Fabric table limits from spec Section 11.18.5.3.
const (
	// MinSupportedFabrics is the minimum supported fabrics (5).
	MinSupportedFabrics = 5
	// MaxSupportedFabrics is the maximum supported fabrics (254).
	MaxSupportedFabrics = 254
	// DefaultSupportedFabrics is the default supported fabrics count.
	DefaultSupportedFabrics = 5
)
