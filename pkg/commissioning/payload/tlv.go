package payload

import (
	"bytes"
	"errors"
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// Matter-common reserved tags for optional TLV data (Spec 5.1.5.2)
const (
	TagSerialNumber         uint8 = 0x00 // UTF-8 string
	TagPBKDFIterations      uint8 = 0x01 // uint32
	TagBPKFSalt             uint8 = 0x02 // octet string (16-32 bytes)
	TagNumberOfDevices      uint8 = 0x03 // uint8
	TagCommissioningTimeout uint8 = 0x04 // uint16 (seconds)
)

// IsCommonTag returns true if the tag is a Matter-common tag (0x00-0x7F).
func IsCommonTag(tag uint8) bool {
	return tag < 0x80
}

// IsVendorTag returns true if the tag is a vendor-specific tag (0x80-0xFF).
func IsVendorTag(tag uint8) bool {
	return tag >= 0x80
}

// OptionalData holds optional TLV data from a QR code payload.
type OptionalData struct {
	// Matter-common fields
	SerialNumber         string
	HasSerialNumber      bool
	PBKDFIterations      uint32
	HasPBKDFIterations   bool
	BPKFSalt             []byte
	NumberOfDevices      uint8
	HasNumberOfDevices   bool
	CommissioningTimeout uint16
	HasCommissioningTimeout bool

	// Vendor-specific data (tag -> value)
	// Values can be string, int64, uint64, or []byte
	VendorData map[uint8]any
}

// TLV parsing errors
var (
	ErrTLVInvalidStructure = errors.New("tlv: expected anonymous structure container")
	ErrTLVInvalidTag       = errors.New("tlv: expected context-specific tag")
	ErrTLVInvalidType      = errors.New("tlv: unexpected element type for tag")
)

// parseTLVData parses optional TLV data from a QR code payload.
// The TLV data must be wrapped in an anonymous structure container.
func parseTLVData(payload *SetupPayload, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	reader := tlv.NewReader(bytes.NewReader(data))

	// Expect anonymous structure container at the top level
	if err := reader.Next(); err != nil {
		if err == io.EOF {
			return nil // No TLV data
		}
		return err
	}

	if reader.Type() != tlv.ElementTypeStruct {
		return ErrTLVInvalidStructure
	}
	if !reader.Tag().IsAnonymous() {
		return ErrTLVInvalidStructure
	}

	// Enter the structure
	if err := reader.EnterContainer(); err != nil {
		return err
	}

	// Initialize optional data if needed
	if payload.OptionalData == nil {
		payload.OptionalData = &OptionalData{}
	}

	// Parse elements inside the structure
	for {
		err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Check for end of container
		if reader.Type() == tlv.ElementTypeEnd {
			break
		}

		// All elements must have context-specific tags
		tag := reader.Tag()
		if !tag.IsContext() {
			return ErrTLVInvalidTag
		}

		tagNum := uint8(tag.TagNumber())

		if IsCommonTag(tagNum) {
			if err := parseCommonTag(payload.OptionalData, reader, tagNum); err != nil {
				return err
			}
		} else {
			if err := parseVendorTag(payload.OptionalData, reader, tagNum); err != nil {
				return err
			}
		}
	}

	return nil
}

// parseCommonTag parses a Matter-common tag.
func parseCommonTag(opt *OptionalData, reader *tlv.Reader, tag uint8) error {
	switch tag {
	case TagSerialNumber:
		// Serial number can be string or uint32
		if reader.Type().IsUTF8String() {
			s, err := reader.String()
			if err != nil {
				return err
			}
			opt.SerialNumber = s
			opt.HasSerialNumber = true
		} else if reader.Type().IsUnsignedInt() {
			v, err := reader.Uint()
			if err != nil {
				return err
			}
			// Convert uint to string representation
			opt.SerialNumber = uintToString(v)
			opt.HasSerialNumber = true
		} else {
			return ErrTLVInvalidType
		}

	case TagPBKDFIterations:
		if !reader.Type().IsUnsignedInt() {
			return ErrTLVInvalidType
		}
		v, err := reader.Uint()
		if err != nil {
			return err
		}
		opt.PBKDFIterations = uint32(v)
		opt.HasPBKDFIterations = true

	case TagBPKFSalt:
		if !reader.Type().IsBytes() {
			return ErrTLVInvalidType
		}
		b, err := reader.Bytes()
		if err != nil {
			return err
		}
		opt.BPKFSalt = b

	case TagNumberOfDevices:
		if !reader.Type().IsUnsignedInt() {
			return ErrTLVInvalidType
		}
		v, err := reader.Uint()
		if err != nil {
			return err
		}
		opt.NumberOfDevices = uint8(v)
		opt.HasNumberOfDevices = true

	case TagCommissioningTimeout:
		if !reader.Type().IsUnsignedInt() {
			return ErrTLVInvalidType
		}
		v, err := reader.Uint()
		if err != nil {
			return err
		}
		opt.CommissioningTimeout = uint16(v)
		opt.HasCommissioningTimeout = true

	default:
		// Unknown common tag - skip it for forward compatibility
		// The value was already read by Next(), so nothing to do
	}

	return nil
}

// parseVendorTag parses a vendor-specific tag.
func parseVendorTag(opt *OptionalData, reader *tlv.Reader, tag uint8) error {
	if opt.VendorData == nil {
		opt.VendorData = make(map[uint8]any)
	}

	switch {
	case reader.Type().IsUTF8String():
		s, err := reader.String()
		if err != nil {
			return err
		}
		opt.VendorData[tag] = s

	case reader.Type().IsSignedInt():
		v, err := reader.Int()
		if err != nil {
			return err
		}
		opt.VendorData[tag] = v

	case reader.Type().IsUnsignedInt():
		v, err := reader.Uint()
		if err != nil {
			return err
		}
		opt.VendorData[tag] = v

	case reader.Type().IsBytes():
		b, err := reader.Bytes()
		if err != nil {
			return err
		}
		opt.VendorData[tag] = b

	default:
		// Skip other types (containers, null, bool, float)
		// The value was already read by Next()
	}

	return nil
}

// uintToString converts a uint64 to its string representation.
func uintToString(v uint64) string {
	if v == 0 {
		return "0"
	}

	// Convert to string using simple division
	var buf [20]byte // Max uint64 is 20 digits
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
