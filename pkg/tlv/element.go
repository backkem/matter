// Package tlv implements the Matter TLV (Tag-Length-Value) encoding format
// as defined in Appendix A of the Matter 1.5 specification.
package tlv

// ElementType represents the type of a TLV element as encoded in the
// lower 5 bits of the control octet (Spec A.7.1).
type ElementType int

const (
	ElementTypeInt8    ElementType = 0x00 // Signed Integer, 1-octet value
	ElementTypeInt16   ElementType = 0x01 // Signed Integer, 2-octet value
	ElementTypeInt32   ElementType = 0x02 // Signed Integer, 4-octet value
	ElementTypeInt64   ElementType = 0x03 // Signed Integer, 8-octet value
	ElementTypeUInt8   ElementType = 0x04 // Unsigned Integer, 1-octet value
	ElementTypeUInt16  ElementType = 0x05 // Unsigned Integer, 2-octet value
	ElementTypeUInt32  ElementType = 0x06 // Unsigned Integer, 4-octet value
	ElementTypeUInt64  ElementType = 0x07 // Unsigned Integer, 8-octet value
	ElementTypeFalse   ElementType = 0x08 // Boolean False
	ElementTypeTrue    ElementType = 0x09 // Boolean True
	ElementTypeFloat32 ElementType = 0x0A // Floating Point, 4-octet value (IEEE 754)
	ElementTypeFloat64 ElementType = 0x0B // Floating Point, 8-octet value (IEEE 754)
	ElementTypeUTF8_1  ElementType = 0x0C // UTF-8 String, 1-octet length
	ElementTypeUTF8_2  ElementType = 0x0D // UTF-8 String, 2-octet length
	ElementTypeUTF8_4  ElementType = 0x0E // UTF-8 String, 4-octet length
	ElementTypeUTF8_8  ElementType = 0x0F // UTF-8 String, 8-octet length
	ElementTypeBytes1  ElementType = 0x10 // Octet String, 1-octet length
	ElementTypeBytes2  ElementType = 0x11 // Octet String, 2-octet length
	ElementTypeBytes4  ElementType = 0x12 // Octet String, 4-octet length
	ElementTypeBytes8  ElementType = 0x13 // Octet String, 8-octet length
	ElementTypeNull    ElementType = 0x14 // Null
	ElementTypeStruct  ElementType = 0x15 // Structure
	ElementTypeArray   ElementType = 0x16 // Array
	ElementTypeList    ElementType = 0x17 // List
	ElementTypeEnd     ElementType = 0x18 // End of Container
)

// String returns the string representation of the element type.
func (e ElementType) String() string {
	switch e {
	case ElementTypeInt8:
		return "Int8"
	case ElementTypeInt16:
		return "Int16"
	case ElementTypeInt32:
		return "Int32"
	case ElementTypeInt64:
		return "Int64"
	case ElementTypeUInt8:
		return "UInt8"
	case ElementTypeUInt16:
		return "UInt16"
	case ElementTypeUInt32:
		return "UInt32"
	case ElementTypeUInt64:
		return "UInt64"
	case ElementTypeFalse:
		return "False"
	case ElementTypeTrue:
		return "True"
	case ElementTypeFloat32:
		return "Float32"
	case ElementTypeFloat64:
		return "Float64"
	case ElementTypeUTF8_1:
		return "UTF8_1"
	case ElementTypeUTF8_2:
		return "UTF8_2"
	case ElementTypeUTF8_4:
		return "UTF8_4"
	case ElementTypeUTF8_8:
		return "UTF8_8"
	case ElementTypeBytes1:
		return "Bytes1"
	case ElementTypeBytes2:
		return "Bytes2"
	case ElementTypeBytes4:
		return "Bytes4"
	case ElementTypeBytes8:
		return "Bytes8"
	case ElementTypeNull:
		return "Null"
	case ElementTypeStruct:
		return "Struct"
	case ElementTypeArray:
		return "Array"
	case ElementTypeList:
		return "List"
	case ElementTypeEnd:
		return "EndOfContainer"
	default:
		return "Unknown"
	}
}

// IsSignedInt returns true if the element type is a signed integer.
func (e ElementType) IsSignedInt() bool {
	return e >= ElementTypeInt8 && e <= ElementTypeInt64
}

// IsUnsignedInt returns true if the element type is an unsigned integer.
func (e ElementType) IsUnsignedInt() bool {
	return e >= ElementTypeUInt8 && e <= ElementTypeUInt64
}

// IsInt returns true if the element type is any integer type.
func (e ElementType) IsInt() bool {
	return e.IsSignedInt() || e.IsUnsignedInt()
}

// IsBool returns true if the element type is a boolean.
func (e ElementType) IsBool() bool {
	return e == ElementTypeFalse || e == ElementTypeTrue
}

// IsFloat returns true if the element type is a floating point number.
func (e ElementType) IsFloat() bool {
	return e == ElementTypeFloat32 || e == ElementTypeFloat64
}

// IsUTF8String returns true if the element type is a UTF-8 string.
func (e ElementType) IsUTF8String() bool {
	return e >= ElementTypeUTF8_1 && e <= ElementTypeUTF8_8
}

// IsBytes returns true if the element type is an octet string.
func (e ElementType) IsBytes() bool {
	return e >= ElementTypeBytes1 && e <= ElementTypeBytes8
}

// IsString returns true if the element type is any string type.
func (e ElementType) IsString() bool {
	return e.IsUTF8String() || e.IsBytes()
}

// IsContainer returns true if the element type is a container (struct, array, list).
func (e ElementType) IsContainer() bool {
	return e == ElementTypeStruct || e == ElementTypeArray || e == ElementTypeList
}

// ValueSize returns the size in bytes of the value field for fixed-size types.
// Returns 0 for variable-length types (strings) and containers.
func (e ElementType) ValueSize() int {
	switch e {
	case ElementTypeInt8, ElementTypeUInt8:
		return 1
	case ElementTypeInt16, ElementTypeUInt16:
		return 2
	case ElementTypeInt32, ElementTypeUInt32, ElementTypeFloat32:
		return 4
	case ElementTypeInt64, ElementTypeUInt64, ElementTypeFloat64:
		return 8
	case ElementTypeFalse, ElementTypeTrue, ElementTypeNull,
		ElementTypeStruct, ElementTypeArray, ElementTypeList, ElementTypeEnd:
		return 0
	default:
		return 0
	}
}

// LengthFieldSize returns the size in bytes of the length field for string types.
// Returns 0 for non-string types.
func (e ElementType) LengthFieldSize() int {
	switch e {
	case ElementTypeUTF8_1, ElementTypeBytes1:
		return 1
	case ElementTypeUTF8_2, ElementTypeBytes2:
		return 2
	case ElementTypeUTF8_4, ElementTypeBytes4:
		return 4
	case ElementTypeUTF8_8, ElementTypeBytes8:
		return 8
	default:
		return 0
	}
}

// controlOctetMasks for parsing/building control octets.
const (
	elementTypeMask = 0x1F // Lower 5 bits
	tagControlMask  = 0xE0 // Upper 3 bits
	tagControlShift = 5
)

// ParseControlOctet extracts the element type and tag control from a control octet.
func ParseControlOctet(b byte) (ElementType, TagControl) {
	elemType := ElementType(b & elementTypeMask)
	tagCtrl := TagControl((b & tagControlMask) >> tagControlShift)
	return elemType, tagCtrl
}

// BuildControlOctet combines an element type and tag control into a control octet.
func BuildControlOctet(elemType ElementType, tagCtrl TagControl) byte {
	return byte(elemType&elementTypeMask) | byte(tagCtrl<<tagControlShift)
}
