package message

import "errors"

// Message layer errors.
var (
	// Header decoding errors
	ErrMessageTooShort     = errors.New("message: data too short")
	ErrInvalidVersion      = errors.New("message: invalid version (must be 0)")
	ErrInvalidSessionType  = errors.New("message: invalid session type (reserved value)")
	ErrInvalidDSIZ         = errors.New("message: invalid DSIZ field (reserved value)")
	ErrMissingSourceNodeID = errors.New("message: group session requires source node ID")

	// Frame errors
	ErrMessageTooLong    = errors.New("message: exceeds maximum size")
	ErrInvalidMIC        = errors.New("message: invalid MIC length")
	ErrPayloadTooShort   = errors.New("message: payload too short for protocol header")
	ErrStreamReadFailed  = errors.New("message: failed to read from stream")
	ErrInvalidLengthPrefix = errors.New("message: invalid length prefix")

	// Security errors
	ErrDecryptionFailed = errors.New("message: decryption/authentication failed")
	ErrInvalidKey       = errors.New("message: invalid encryption key")
	ErrInvalidNonce     = errors.New("message: invalid nonce")

	// Counter errors
	ErrReplayDetected    = errors.New("message: replay detected (duplicate counter)")
	ErrCounterExhausted  = errors.New("message: message counter exhausted")
	ErrCounterOutOfRange = errors.New("message: counter outside valid window")
)

// Message format constants from Matter Specification.
const (
	// MessageVersion is the only supported message format version (Section 4.4.1.1).
	MessageVersion uint8 = 0

	// MinHeaderSize is the minimum message header size in bytes.
	// Message Flags (1) + Session ID (2) + Security Flags (1) + Message Counter (4) = 8
	MinHeaderSize = 8

	// MinProtocolHeaderSize is the minimum protocol header size in bytes.
	// Exchange Flags (1) + Opcode (1) + Exchange ID (2) + Protocol ID (2) = 6
	MinProtocolHeaderSize = 6

	// MaxUDPMessageSize is the maximum message size for UDP transport.
	// This is the IPv6 minimum MTU (Section 4.4.4).
	MaxUDPMessageSize = 1280

	// MICSize is the Message Integrity Check size in bytes.
	// AES-CCM with 128-bit tag (Section 3.6).
	MICSize = 16

	// NodeIDSize is the size of a 64-bit Node ID in bytes.
	NodeIDSize = 8

	// GroupIDSize is the size of a 16-bit Group ID in bytes.
	GroupIDSize = 2

	// TCPLengthPrefixSize is the size of the TCP length prefix (Section 4.5.1).
	TCPLengthPrefixSize = 4

	// BTPLengthPrefixSize is the size of the BTP/PAFTP length prefix.
	BTPLengthPrefixSize = 2
)

// Message Flags bit positions (Section 4.4.1.1).
const (
	// flagDSIZMask is the mask for DSIZ field (bits 0-1).
	flagDSIZMask uint8 = 0x03

	// flagSourcePresent is the S Flag position (bit 2).
	flagSourcePresent uint8 = 0x04

	// flagVersionShift is the bit shift for Version field (bits 4-7).
	flagVersionShift = 4

	// flagVersionMask is the mask for Version field after shifting.
	flagVersionMask uint8 = 0x0F
)

// Security Flags bit positions (Section 4.4.1.3).
const (
	// secFlagSessionTypeMask is the mask for Session Type (bits 0-1).
	secFlagSessionTypeMask uint8 = 0x03

	// secFlagExtensions is the MX Flag position (bit 5).
	secFlagExtensions uint8 = 0x20

	// secFlagControl is the C Flag position (bit 6).
	secFlagControl uint8 = 0x40

	// secFlagPrivacy is the P Flag position (bit 7).
	secFlagPrivacy uint8 = 0x80
)

// Exchange Flags bit positions (Section 4.4.3.1).
const (
	// exchFlagInitiator is the I Flag position (bit 0).
	exchFlagInitiator uint8 = 0x01

	// exchFlagAcknowledgement is the A Flag position (bit 1).
	exchFlagAcknowledgement uint8 = 0x02

	// exchFlagReliability is the R Flag position (bit 2).
	exchFlagReliability uint8 = 0x04

	// exchFlagSecuredExtensions is the SX Flag position (bit 3).
	exchFlagSecuredExtensions uint8 = 0x08

	// exchFlagVendor is the V Flag position (bit 4).
	exchFlagVendor uint8 = 0x10
)

// Counter constants (Section 4.6).
const (
	// CounterWindowSize is MSG_COUNTER_WINDOW_SIZE for replay detection.
	CounterWindowSize = 32

	// CounterInitMax is the maximum initial counter value (2^28).
	// Counters are initialized to random values in [1, CounterInitMax].
	CounterInitMax = 1 << 28
)

// Special node ID values.
const (
	// UnspecifiedNodeID is used for PASE sessions (no operational identity yet).
	UnspecifiedNodeID uint64 = 0
)
