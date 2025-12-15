package payload

import (
	"errors"
	"strings"
)

// QR code constants
const (
	// QRCodePrefix is the prefix for all Matter QR codes.
	QRCodePrefix = "MT:"

	// PayloadDelimiter separates multiple payloads in concatenated QR codes.
	PayloadDelimiter = '*'
)

// Bit field lengths (from spec Section 5.1.2)
const (
	versionFieldBits           = 3
	vendorIDFieldBits          = 16
	productIDFieldBits         = 16
	commissioningFlowFieldBits = 2
	rendezvousInfoFieldBits    = 8
	discriminatorFieldBits     = 12
	passcodeFieldBits          = 27
	paddingFieldBits           = 4

	// Total: 3+16+16+2+8+12+27+4 = 88 bits = 11 bytes
	totalPayloadBits  = 88
	totalPayloadBytes = 11
)

// QR code parsing errors
var (
	ErrQRCodeInvalidPrefix  = errors.New("qrcode: invalid prefix (expected MT:)")
	ErrQRCodeTooShort       = errors.New("qrcode: payload too short")
	ErrQRCodeInvalidPadding = errors.New("qrcode: invalid padding (must be zero)")
)

// ParseQRCode decodes a Matter QR code string into a SetupPayload.
//
// The QR code format is: MT:<base38-encoded-data>
// The base38 data contains packed binary fields followed by optional TLV data.
func ParseQRCode(qrCode string) (*SetupPayload, error) {
	payloads, err := ParseQRCodes(qrCode)
	if err != nil {
		return nil, err
	}
	if len(payloads) == 0 {
		return nil, ErrQRCodeTooShort
	}
	if len(payloads) > 1 {
		return nil, errors.New("qrcode: use ParseQRCodes for concatenated QR codes")
	}
	return payloads[0], nil
}

// ParseQRCodes decodes a Matter QR code string that may contain multiple
// concatenated payloads separated by '*'.
func ParseQRCodes(qrCode string) ([]*SetupPayload, error) {
	// Extract the base38 portion
	base38Data := ExtractPayload(qrCode)
	if base38Data == "" {
		return nil, ErrQRCodeTooShort
	}

	// Split by delimiter for concatenated payloads
	chunks := strings.Split(base38Data, string(PayloadDelimiter))
	payloads := make([]*SetupPayload, 0, len(chunks))

	for _, chunk := range chunks {
		if chunk == "" {
			continue
		}

		payload, err := parseBase38Payload(chunk)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, payload)
	}

	return payloads, nil
}

// ExtractPayload extracts the base38 payload from a QR code string.
// Handles URL-encoded QR codes with '%' delimiters.
//
// Examples:
//   - "MT:ABC" → "ABC"
//   - "Z%MT:ABC%DDD" → "ABC"
//   - "%Z%MT:ABC%DDD" → "ABC"
func ExtractPayload(qrCode string) string {
	// Find segments delimited by '%'
	var segments []string
	start := 0
	for i := 0; i <= len(qrCode); i++ {
		if i == len(qrCode) || qrCode[i] == '%' {
			if i > start {
				segments = append(segments, qrCode[start:i])
			}
			start = i + 1
		}
	}

	// Find the first segment that starts with MT:
	for _, segment := range segments {
		if strings.HasPrefix(segment, QRCodePrefix) && len(segment) > len(QRCodePrefix) {
			return segment[len(QRCodePrefix):]
		}
	}

	return ""
}

// parseBase38Payload parses a single base38-encoded payload chunk.
func parseBase38Payload(base38 string) (*SetupPayload, error) {
	// Decode base38 to bytes
	data, err := Base38Decode(base38)
	if err != nil {
		return nil, err
	}

	if len(data) < totalPayloadBytes {
		return nil, ErrQRCodeTooShort
	}

	// Read bits from the decoded data
	reader := &bitReader{data: data}

	payload := &SetupPayload{
		HasDiscoveryCapabilities: true, // QR codes always have this
	}

	// Read fields in order (LSB first in the byte array)
	version, _ := reader.readBits(versionFieldBits)
	payload.Version = uint8(version)

	vendorID, _ := reader.readBits(vendorIDFieldBits)
	payload.VendorID = uint16(vendorID)

	productID, _ := reader.readBits(productIDFieldBits)
	payload.ProductID = uint16(productID)

	flow, _ := reader.readBits(commissioningFlowFieldBits)
	payload.CommissioningFlow = CommissioningFlow(flow)

	rendezvous, _ := reader.readBits(rendezvousInfoFieldBits)
	payload.DiscoveryCapabilities = DiscoveryCapabilities(rendezvous)

	discriminator, _ := reader.readBits(discriminatorFieldBits)
	payload.Discriminator = NewLongDiscriminator(uint16(discriminator))

	passcode, _ := reader.readBits(passcodeFieldBits)
	payload.Passcode = uint32(passcode)

	padding, _ := reader.readBits(paddingFieldBits)
	if padding != 0 {
		return nil, ErrQRCodeInvalidPadding
	}

	// Parse optional TLV data if present
	if len(data) > totalPayloadBytes {
		if err := parseTLVData(payload, data[totalPayloadBytes:]); err != nil {
			return nil, err
		}
	}

	return payload, nil
}

// EncodeQRCode encodes a SetupPayload to a QR code string.
func EncodeQRCode(payload *SetupPayload) (string, error) {
	if !payload.IsValidQRCodePayload(ValidationModeProduce) {
		return "", errors.New("qrcode: invalid payload for QR code")
	}

	// Build the bit array
	writer := &bitWriter{}

	writer.writeBits(uint64(payload.Version), versionFieldBits)
	writer.writeBits(uint64(payload.VendorID), vendorIDFieldBits)
	writer.writeBits(uint64(payload.ProductID), productIDFieldBits)
	writer.writeBits(uint64(payload.CommissioningFlow), commissioningFlowFieldBits)
	writer.writeBits(uint64(payload.DiscoveryCapabilities), rendezvousInfoFieldBits)
	writer.writeBits(uint64(payload.Discriminator.Long()), discriminatorFieldBits)
	writer.writeBits(uint64(payload.Passcode), passcodeFieldBits)
	writer.writeBits(0, paddingFieldBits) // Padding must be zero

	// TODO: Encode optional TLV data if present

	// Encode to base38
	base38 := Base38Encode(writer.bytes())

	return QRCodePrefix + base38, nil
}

// bitReader reads bits from a byte slice (LSB first).
type bitReader struct {
	data  []byte
	index int // Current bit index
}

// readBits reads n bits from the data and returns the value.
func (r *bitReader) readBits(n int) (uint64, error) {
	if r.index+n > len(r.data)*8 {
		return 0, errors.New("bitReader: not enough bits")
	}

	var value uint64
	for i := 0; i < n; i++ {
		byteIdx := (r.index + i) / 8
		bitIdx := (r.index + i) % 8

		if r.data[byteIdx]&(1<<bitIdx) != 0 {
			value |= 1 << i
		}
	}

	r.index += n
	return value, nil
}

// bitWriter writes bits to a byte slice (LSB first).
type bitWriter struct {
	data  []byte
	index int // Current bit index
}

// writeBits writes n bits of value to the data.
func (w *bitWriter) writeBits(value uint64, n int) {
	// Ensure we have enough bytes
	neededBytes := (w.index + n + 7) / 8
	for len(w.data) < neededBytes {
		w.data = append(w.data, 0)
	}

	for i := 0; i < n; i++ {
		if value&(1<<i) != 0 {
			byteIdx := (w.index + i) / 8
			bitIdx := (w.index + i) % 8
			w.data[byteIdx] |= 1 << bitIdx
		}
	}

	w.index += n
}

// bytes returns the accumulated byte slice.
func (w *bitWriter) bytes() []byte {
	return w.data
}

