// Package message implements Matter message framing, encoding, and security.
// This package handles the wire format for Matter protocol messages as defined
// in Matter Specification Chapter 4.
//
// The package provides:
//   - Message and Protocol header encoding/decoding
//   - Secure message encryption/decryption (AES-CCM)
//   - Privacy header obfuscation (AES-CTR)
//   - Message counter management and replay detection
//   - TCP stream framing support
package message

// SessionType identifies the type of session associated with a message.
// This is encoded in the Security Flags field (bits 0-1).
// See Matter Specification Section 4.4.1.3.
type SessionType uint8

const (
	// SessionTypeUnicast indicates a unicast session (PASE or CASE).
	// Session ID of 0 with this type indicates an unsecured session.
	SessionTypeUnicast SessionType = 0

	// SessionTypeGroup indicates a group session using group keys.
	SessionTypeGroup SessionType = 1
)

// String returns a human-readable name for the session type.
func (s SessionType) String() string {
	switch s {
	case SessionTypeUnicast:
		return "Unicast"
	case SessionTypeGroup:
		return "Group"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the session type is a defined value.
func (s SessionType) IsValid() bool {
	return s <= SessionTypeGroup
}

// DestinationType identifies the format of the Destination Node ID field.
// This is encoded in the Message Flags DSIZ field (bits 0-1).
// See Matter Specification Section 4.4.1.1.
type DestinationType uint8

const (
	// DestinationNone indicates no Destination Node ID field is present.
	DestinationNone DestinationType = 0

	// DestinationNodeID indicates a 64-bit Node ID is present.
	DestinationNodeID DestinationType = 1

	// DestinationGroupID indicates a 16-bit Group ID is present.
	DestinationGroupID DestinationType = 2
)

// String returns a human-readable name for the destination type.
func (d DestinationType) String() string {
	switch d {
	case DestinationNone:
		return "None"
	case DestinationNodeID:
		return "NodeID"
	case DestinationGroupID:
		return "GroupID"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the destination type is a defined value.
func (d DestinationType) IsValid() bool {
	return d <= DestinationGroupID
}

// Size returns the size in bytes of the destination field for this type.
func (d DestinationType) Size() int {
	switch d {
	case DestinationNone:
		return 0
	case DestinationNodeID:
		return 8
	case DestinationGroupID:
		return 2
	default:
		return 0
	}
}

// ProtocolID identifies the protocol that defines the message opcode.
// See Matter Specification Section 4.4.3.4.
type ProtocolID uint16

const (
	// ProtocolSecureChannel is the Secure Channel Protocol (PASE, CASE, MRP).
	ProtocolSecureChannel ProtocolID = 0x0000

	// ProtocolInteractionModel is the Interaction Model Protocol.
	ProtocolInteractionModel ProtocolID = 0x0001

	// ProtocolBDX is the Bulk Data Exchange Protocol.
	ProtocolBDX ProtocolID = 0x0002

	// ProtocolUserDirectedCommissioning is the UDC Protocol.
	ProtocolUserDirectedCommissioning ProtocolID = 0x0003

	// ProtocolForTesting is reserved for isolated test environments.
	ProtocolForTesting ProtocolID = 0x0004
)

// String returns a human-readable name for the protocol ID.
func (p ProtocolID) String() string {
	switch p {
	case ProtocolSecureChannel:
		return "SecureChannel"
	case ProtocolInteractionModel:
		return "InteractionModel"
	case ProtocolBDX:
		return "BDX"
	case ProtocolUserDirectedCommissioning:
		return "UDC"
	case ProtocolForTesting:
		return "Testing"
	default:
		return "Unknown"
	}
}

// VendorID constants.
const (
	// VendorIDMatter is the standard Matter vendor ID (0x0000).
	VendorIDMatter uint16 = 0x0000
)
