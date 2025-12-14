package message

import (
	"encoding/binary"
)

// ProtocolHeader represents the Matter protocol message header (Spec Section 4.4.3).
// This is the first part of the Message Payload, which is encrypted for secure sessions.
type ProtocolHeader struct {
	// ProtocolID identifies the protocol that defines the opcode.
	ProtocolID ProtocolID

	// ProtocolOpcode identifies the message type within the protocol.
	ProtocolOpcode uint8

	// ExchangeID identifies the exchange (conversation) this message belongs to.
	ExchangeID uint16

	// ProtocolVendorID namespaces the ProtocolID.
	// Only present when VendorPresent is true; defaults to VendorIDMatter (0).
	ProtocolVendorID uint16

	// AckedMessageCounter is the counter of a previously received message being acknowledged.
	// Only valid when Acknowledgement is true.
	AckedMessageCounter uint32

	// Initiator indicates this message was sent by the exchange initiator (I Flag).
	Initiator bool

	// Acknowledgement indicates this message acknowledges a previous message (A Flag).
	Acknowledgement bool

	// Reliability indicates the sender wants an acknowledgement (R Flag).
	Reliability bool

	// SecuredExtensions indicates secured extensions are present (SX Flag).
	// Note: Version 1.0 nodes must set this to false.
	SecuredExtensions bool

	// VendorPresent indicates ProtocolVendorID is included (V Flag).
	VendorPresent bool
}

// Size returns the encoded size of the protocol header in bytes.
func (p *ProtocolHeader) Size() int {
	size := MinProtocolHeaderSize // Exchange Flags + Opcode + Exchange ID + Protocol ID

	if p.VendorPresent {
		size += 2 // Protocol Vendor ID
	}

	if p.Acknowledgement {
		size += 4 // Acked Message Counter
	}

	return size
}

// Encode serializes the protocol header to bytes.
func (p *ProtocolHeader) Encode() []byte {
	buf := make([]byte, p.Size())
	p.EncodeTo(buf)
	return buf
}

// EncodeTo serializes the protocol header into the provided buffer.
// The buffer must be at least Size() bytes long.
// Returns the number of bytes written.
func (p *ProtocolHeader) EncodeTo(buf []byte) int {
	offset := 0

	// Exchange Flags byte
	buf[offset] = p.exchangeFlags()
	offset++

	// Protocol Opcode
	buf[offset] = p.ProtocolOpcode
	offset++

	// Exchange ID (2 bytes, little-endian)
	binary.LittleEndian.PutUint16(buf[offset:], p.ExchangeID)
	offset += 2

	// Protocol Vendor ID (optional, 2 bytes)
	if p.VendorPresent {
		binary.LittleEndian.PutUint16(buf[offset:], p.ProtocolVendorID)
		offset += 2
	}

	// Protocol ID (2 bytes, little-endian)
	binary.LittleEndian.PutUint16(buf[offset:], uint16(p.ProtocolID))
	offset += 2

	// Acked Message Counter (optional, 4 bytes)
	if p.Acknowledgement {
		binary.LittleEndian.PutUint32(buf[offset:], p.AckedMessageCounter)
		offset += 4
	}

	return offset
}

// exchangeFlags constructs the Exchange Flags byte.
func (p *ProtocolHeader) exchangeFlags() uint8 {
	var flags uint8

	if p.Initiator {
		flags |= exchFlagInitiator
	}

	if p.Acknowledgement {
		flags |= exchFlagAcknowledgement
	}

	if p.Reliability {
		flags |= exchFlagReliability
	}

	if p.SecuredExtensions {
		flags |= exchFlagSecuredExtensions
	}

	if p.VendorPresent {
		flags |= exchFlagVendor
	}

	return flags
}

// Decode deserializes a protocol header from bytes.
// Returns the number of bytes consumed from data.
func (p *ProtocolHeader) Decode(data []byte) (int, error) {
	if len(data) < MinProtocolHeaderSize {
		return 0, ErrPayloadTooShort
	}

	offset := 0

	// Exchange Flags byte
	exchFlags := data[offset]
	offset++

	// Parse flags
	p.Initiator = (exchFlags & exchFlagInitiator) != 0
	p.Acknowledgement = (exchFlags & exchFlagAcknowledgement) != 0
	p.Reliability = (exchFlags & exchFlagReliability) != 0
	p.SecuredExtensions = (exchFlags & exchFlagSecuredExtensions) != 0
	p.VendorPresent = (exchFlags & exchFlagVendor) != 0

	// Protocol Opcode
	p.ProtocolOpcode = data[offset]
	offset++

	// Exchange ID (2 bytes)
	p.ExchangeID = binary.LittleEndian.Uint16(data[offset:])
	offset += 2

	// Calculate remaining required bytes
	requiredLen := offset + 2 // Protocol ID
	if p.VendorPresent {
		requiredLen += 2
	}
	if p.Acknowledgement {
		requiredLen += 4
	}

	if len(data) < requiredLen {
		return 0, ErrPayloadTooShort
	}

	// Protocol Vendor ID (optional)
	if p.VendorPresent {
		p.ProtocolVendorID = binary.LittleEndian.Uint16(data[offset:])
		offset += 2
	} else {
		p.ProtocolVendorID = VendorIDMatter
	}

	// Protocol ID (2 bytes)
	p.ProtocolID = ProtocolID(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2

	// Acked Message Counter (optional)
	if p.Acknowledgement {
		p.AckedMessageCounter = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
	} else {
		p.AckedMessageCounter = 0
	}

	return offset, nil
}

// IsSecureChannel returns true if this is a Secure Channel Protocol message.
func (p *ProtocolHeader) IsSecureChannel() bool {
	return p.ProtocolVendorID == VendorIDMatter && p.ProtocolID == ProtocolSecureChannel
}

// IsInteractionModel returns true if this is an Interaction Model Protocol message.
func (p *ProtocolHeader) IsInteractionModel() bool {
	return p.ProtocolVendorID == VendorIDMatter && p.ProtocolID == ProtocolInteractionModel
}

// NeedsAck returns true if this message requires an acknowledgement.
func (p *ProtocolHeader) NeedsAck() bool {
	return p.Reliability
}

// IsAck returns true if this message is an acknowledgement.
func (p *ProtocolHeader) IsAck() bool {
	return p.Acknowledgement
}
