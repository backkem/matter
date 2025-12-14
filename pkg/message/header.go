package message

import (
	"encoding/binary"
)

// MessageHeader represents the Matter message header (Spec Section 4.4.1).
// All multi-byte fields are little-endian on the wire.
type MessageHeader struct {
	// SessionID identifies the session (encryption context) for this message.
	// A SessionID of 0 with SessionTypeUnicast indicates an unsecured session.
	SessionID uint16

	// MessageCounter is a monotonically increasing counter unique per message.
	// Used for replay detection and as part of the encryption nonce.
	MessageCounter uint32

	// SessionType indicates unicast or group session.
	SessionType SessionType

	// SourceNodeID is the 64-bit source node identifier.
	// Present only when SourcePresent is true.
	// Required for group messages; optional for unicast.
	SourceNodeID uint64

	// DestinationType indicates the format of the destination field.
	DestinationType DestinationType

	// DestinationNodeID is the 64-bit destination node identifier.
	// Valid only when DestinationType is DestinationNodeID.
	DestinationNodeID uint64

	// DestinationGroupID is the 16-bit destination group identifier.
	// Valid only when DestinationType is DestinationGroupID.
	DestinationGroupID uint16

	// SourcePresent indicates whether SourceNodeID is included (S Flag).
	SourcePresent bool

	// Privacy indicates whether privacy obfuscation is applied (P Flag).
	Privacy bool

	// Control indicates this is a control message using control counter (C Flag).
	Control bool

	// Extensions indicates message extensions are present (MX Flag).
	// Note: Version 1.0 nodes must set this to false.
	Extensions bool
}

// Size returns the encoded size of the message header in bytes.
func (h *MessageHeader) Size() int {
	size := MinHeaderSize // Message Flags + Session ID + Security Flags + Counter

	if h.SourcePresent {
		size += NodeIDSize
	}

	size += h.DestinationType.Size()

	return size
}

// Encode serializes the message header to bytes.
// The returned slice can be used directly as AAD for encryption.
func (h *MessageHeader) Encode() []byte {
	buf := make([]byte, h.Size())
	h.EncodeTo(buf)
	return buf
}

// EncodeTo serializes the message header into the provided buffer.
// The buffer must be at least Size() bytes long.
// Returns the number of bytes written.
func (h *MessageHeader) EncodeTo(buf []byte) int {
	offset := 0

	// Message Flags byte
	buf[offset] = h.messageFlags()
	offset++

	// Session ID (2 bytes, little-endian)
	binary.LittleEndian.PutUint16(buf[offset:], h.SessionID)
	offset += 2

	// Security Flags byte
	buf[offset] = h.securityFlags()
	offset++

	// Message Counter (4 bytes, little-endian)
	binary.LittleEndian.PutUint32(buf[offset:], h.MessageCounter)
	offset += 4

	// Source Node ID (optional, 8 bytes)
	if h.SourcePresent {
		binary.LittleEndian.PutUint64(buf[offset:], h.SourceNodeID)
		offset += NodeIDSize
	}

	// Destination (optional, 2 or 8 bytes)
	switch h.DestinationType {
	case DestinationNodeID:
		binary.LittleEndian.PutUint64(buf[offset:], h.DestinationNodeID)
		offset += NodeIDSize
	case DestinationGroupID:
		binary.LittleEndian.PutUint16(buf[offset:], h.DestinationGroupID)
		offset += GroupIDSize
	}

	return offset
}

// messageFlags constructs the Message Flags byte.
func (h *MessageHeader) messageFlags() uint8 {
	var flags uint8

	// Version in bits 4-7 (always 0 for v1.0)
	flags |= MessageVersion << flagVersionShift

	// S Flag in bit 2
	if h.SourcePresent {
		flags |= flagSourcePresent
	}

	// DSIZ in bits 0-1
	flags |= uint8(h.DestinationType) & flagDSIZMask

	return flags
}

// securityFlags constructs the Security Flags byte.
func (h *MessageHeader) securityFlags() uint8 {
	var flags uint8

	// Session Type in bits 0-1
	flags |= uint8(h.SessionType) & secFlagSessionTypeMask

	// MX Flag in bit 5
	if h.Extensions {
		flags |= secFlagExtensions
	}

	// C Flag in bit 6
	if h.Control {
		flags |= secFlagControl
	}

	// P Flag in bit 7
	if h.Privacy {
		flags |= secFlagPrivacy
	}

	return flags
}

// Decode deserializes a message header from bytes.
// Returns the number of bytes consumed from data.
func (h *MessageHeader) Decode(data []byte) (int, error) {
	if len(data) < MinHeaderSize {
		return 0, ErrMessageTooShort
	}

	offset := 0

	// Message Flags byte
	msgFlags := data[offset]
	offset++

	// Parse version (bits 4-7)
	version := (msgFlags >> flagVersionShift) & flagVersionMask
	if version != MessageVersion {
		return 0, ErrInvalidVersion
	}

	// Parse S Flag (bit 2)
	h.SourcePresent = (msgFlags & flagSourcePresent) != 0

	// Parse DSIZ (bits 0-1)
	h.DestinationType = DestinationType(msgFlags & flagDSIZMask)
	if !h.DestinationType.IsValid() {
		return 0, ErrInvalidDSIZ
	}

	// Session ID (2 bytes)
	h.SessionID = binary.LittleEndian.Uint16(data[offset:])
	offset += 2

	// Security Flags byte
	secFlags := data[offset]
	offset++

	// Parse Session Type (bits 0-1)
	h.SessionType = SessionType(secFlags & secFlagSessionTypeMask)
	if !h.SessionType.IsValid() {
		return 0, ErrInvalidSessionType
	}

	// Parse MX Flag (bit 5)
	h.Extensions = (secFlags & secFlagExtensions) != 0

	// Parse C Flag (bit 6)
	h.Control = (secFlags & secFlagControl) != 0

	// Parse P Flag (bit 7)
	h.Privacy = (secFlags & secFlagPrivacy) != 0

	// Message Counter (4 bytes)
	h.MessageCounter = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// Calculate remaining required bytes
	requiredLen := offset
	if h.SourcePresent {
		requiredLen += NodeIDSize
	}
	requiredLen += h.DestinationType.Size()

	if len(data) < requiredLen {
		return 0, ErrMessageTooShort
	}

	// Source Node ID (optional)
	if h.SourcePresent {
		h.SourceNodeID = binary.LittleEndian.Uint64(data[offset:])
		offset += NodeIDSize
	} else {
		h.SourceNodeID = 0
	}

	// Destination (optional)
	switch h.DestinationType {
	case DestinationNodeID:
		h.DestinationNodeID = binary.LittleEndian.Uint64(data[offset:])
		h.DestinationGroupID = 0
		offset += NodeIDSize
	case DestinationGroupID:
		h.DestinationGroupID = binary.LittleEndian.Uint16(data[offset:])
		h.DestinationNodeID = 0
		offset += GroupIDSize
	default:
		h.DestinationNodeID = 0
		h.DestinationGroupID = 0
	}

	return offset, nil
}

// IsSecure returns true if this message uses encryption (not an unsecured session).
func (h *MessageHeader) IsSecure() bool {
	// Unsecured session is indicated by SessionType=Unicast AND SessionID=0
	return !(h.SessionType == SessionTypeUnicast && h.SessionID == 0)
}

// Validate checks the header for spec compliance.
// Returns an error if the header violates any constraints.
func (h *MessageHeader) Validate() error {
	// Group sessions require source node ID (Spec 4.7.2.1.c.ii)
	if h.SessionType == SessionTypeGroup && !h.SourcePresent {
		return ErrMissingSourceNodeID
	}

	// Group sessions must have a destination (Spec 4.7.2.1.c.i)
	if h.SessionType == SessionTypeGroup && h.DestinationType == DestinationNone {
		return ErrInvalidDSIZ
	}

	// Unicast sessions should not have Group ID destination
	if h.SessionType == SessionTypeUnicast && h.DestinationType == DestinationGroupID {
		return ErrInvalidDSIZ
	}

	return nil
}

// PrivacyObfuscatedSize returns the size of the privacy-obfuscated portion.
// This is: Message Counter + [Source Node ID] + [Destination]
func (h *MessageHeader) PrivacyObfuscatedSize() int {
	size := 4 // Message Counter

	if h.SourcePresent {
		size += NodeIDSize
	}

	size += h.DestinationType.Size()

	return size
}

// PrivacyHeaderOffset returns the byte offset where privacy obfuscation starts.
// This is after: Message Flags (1) + Session ID (2) + Security Flags (1) = 4
func (h *MessageHeader) PrivacyHeaderOffset() int {
	return 4
}
