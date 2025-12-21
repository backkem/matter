package tlv

import (
	"encoding/binary"
	"io"
	"math"
	"unicode/utf8"
)

// Writer encodes TLV elements to an io.Writer.
type Writer struct {
	w              io.Writer
	containerStack []ElementType // Track open containers for validation
}

// NewWriter creates a new TLV Writer that writes to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// writeControlAndTag writes the control octet and tag.
func (w *Writer) writeControlAndTag(elemType ElementType, tag Tag) error {
	ctrl := BuildControlOctet(elemType, tag.Control())
	if _, err := w.w.Write([]byte{ctrl}); err != nil {
		return err
	}
	_, err := tag.WriteTo(w.w)
	return err
}

// PutInt writes a signed integer with the given tag.
// The writer chooses the minimum width needed to encode the value.
func (w *Writer) PutInt(tag Tag, v int64) error {
	var elemType ElementType
	var buf [8]byte

	switch {
	case v >= math.MinInt8 && v <= math.MaxInt8:
		elemType = ElementTypeInt8
		buf[0] = byte(v)
		return w.writeFixedValue(elemType, tag, buf[:1])
	case v >= math.MinInt16 && v <= math.MaxInt16:
		elemType = ElementTypeInt16
		binary.LittleEndian.PutUint16(buf[:2], uint16(v))
		return w.writeFixedValue(elemType, tag, buf[:2])
	case v >= math.MinInt32 && v <= math.MaxInt32:
		elemType = ElementTypeInt32
		binary.LittleEndian.PutUint32(buf[:4], uint32(v))
		return w.writeFixedValue(elemType, tag, buf[:4])
	default:
		elemType = ElementTypeInt64
		binary.LittleEndian.PutUint64(buf[:8], uint64(v))
		return w.writeFixedValue(elemType, tag, buf[:8])
	}
}

// PutIntWithWidth writes a signed integer with a specific width (1, 2, 4, or 8 bytes).
// This is useful when you need to match a specific encoding.
func (w *Writer) PutIntWithWidth(tag Tag, v int64, width int) error {
	var elemType ElementType
	var buf [8]byte

	switch width {
	case 1:
		elemType = ElementTypeInt8
		buf[0] = byte(v)
		return w.writeFixedValue(elemType, tag, buf[:1])
	case 2:
		elemType = ElementTypeInt16
		binary.LittleEndian.PutUint16(buf[:2], uint16(v))
		return w.writeFixedValue(elemType, tag, buf[:2])
	case 4:
		elemType = ElementTypeInt32
		binary.LittleEndian.PutUint32(buf[:4], uint32(v))
		return w.writeFixedValue(elemType, tag, buf[:4])
	case 8:
		elemType = ElementTypeInt64
		binary.LittleEndian.PutUint64(buf[:8], uint64(v))
		return w.writeFixedValue(elemType, tag, buf[:8])
	default:
		return ErrInvalidElementType
	}
}

// PutUint writes an unsigned integer with the given tag.
// The writer chooses the minimum width needed to encode the value.
func (w *Writer) PutUint(tag Tag, v uint64) error {
	var elemType ElementType
	var buf [8]byte

	switch {
	case v <= math.MaxUint8:
		elemType = ElementTypeUInt8
		buf[0] = byte(v)
		return w.writeFixedValue(elemType, tag, buf[:1])
	case v <= math.MaxUint16:
		elemType = ElementTypeUInt16
		binary.LittleEndian.PutUint16(buf[:2], uint16(v))
		return w.writeFixedValue(elemType, tag, buf[:2])
	case v <= math.MaxUint32:
		elemType = ElementTypeUInt32
		binary.LittleEndian.PutUint32(buf[:4], uint32(v))
		return w.writeFixedValue(elemType, tag, buf[:4])
	default:
		elemType = ElementTypeUInt64
		binary.LittleEndian.PutUint64(buf[:8], v)
		return w.writeFixedValue(elemType, tag, buf[:8])
	}
}

// PutUintWithWidth writes an unsigned integer with a specific width (1, 2, 4, or 8 bytes).
func (w *Writer) PutUintWithWidth(tag Tag, v uint64, width int) error {
	var elemType ElementType
	var buf [8]byte

	switch width {
	case 1:
		elemType = ElementTypeUInt8
		buf[0] = byte(v)
		return w.writeFixedValue(elemType, tag, buf[:1])
	case 2:
		elemType = ElementTypeUInt16
		binary.LittleEndian.PutUint16(buf[:2], uint16(v))
		return w.writeFixedValue(elemType, tag, buf[:2])
	case 4:
		elemType = ElementTypeUInt32
		binary.LittleEndian.PutUint32(buf[:4], uint32(v))
		return w.writeFixedValue(elemType, tag, buf[:4])
	case 8:
		elemType = ElementTypeUInt64
		binary.LittleEndian.PutUint64(buf[:8], v)
		return w.writeFixedValue(elemType, tag, buf[:8])
	default:
		return ErrInvalidElementType
	}
}

// PutBool writes a boolean with the given tag.
func (w *Writer) PutBool(tag Tag, v bool) error {
	elemType := ElementTypeFalse
	if v {
		elemType = ElementTypeTrue
	}
	return w.writeControlAndTag(elemType, tag)
}

// PutFloat32 writes a 32-bit floating point number with the given tag.
func (w *Writer) PutFloat32(tag Tag, v float32) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], math.Float32bits(v))
	return w.writeFixedValue(ElementTypeFloat32, tag, buf[:])
}

// PutFloat64 writes a 64-bit floating point number with the given tag.
func (w *Writer) PutFloat64(tag Tag, v float64) error {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], math.Float64bits(v))
	return w.writeFixedValue(ElementTypeFloat64, tag, buf[:])
}

// PutString writes a UTF-8 string with the given tag.
// Returns ErrInvalidUTF8 if the string is not valid UTF-8.
func (w *Writer) PutString(tag Tag, v string) error {
	if !utf8.ValidString(v) {
		return ErrInvalidUTF8
	}
	return w.writeStringValue(true, tag, []byte(v))
}

// PutBytes writes an octet string (byte slice) with the given tag.
func (w *Writer) PutBytes(tag Tag, v []byte) error {
	return w.writeStringValue(false, tag, v)
}

// PutRaw writes raw TLV bytes with the given tag.
// The provided bytes must start with a TLV control byte and be a complete TLV element.
// This replaces the tag in the raw TLV with the provided tag.
// This is used when embedding pre-encoded TLV (with anonymous tag) within a container.
func (w *Writer) PutRaw(tag Tag, rawTLV []byte) error {
	if len(rawTLV) == 0 {
		return nil
	}

	// The rawTLV should start with a control byte
	// Extract the element type from the control byte
	controlByte := rawTLV[0]
	elemType := ElementType(controlByte & 0x1F) // Lower 5 bits are element type

	// Write the new control byte with our tag
	if err := w.writeControlAndTag(elemType, tag); err != nil {
		return err
	}

	// Write the rest of the TLV data (skip original control byte and tag)
	// Need to determine how many bytes to skip based on tag control
	originalTagControl := TagControl((controlByte >> 5) & 0x07) // Upper 3 bits are tag control
	skipBytes := 1 // At least the control byte

	// Skip tag bytes based on tag control type
	switch originalTagControl {
	case TagControlAnonymous:
		// No tag bytes
	case TagControlContext:
		skipBytes += 1 // 1-byte tag number
	case TagControlCommonProfile2, TagControlImplicitProfile2:
		skipBytes += 2 // 2-byte tag
	case TagControlCommonProfile4, TagControlImplicitProfile4:
		skipBytes += 4 // 4-byte tag
	case TagControlFullyQualified6:
		skipBytes += 6 // 6-byte tag (2-byte vendor + 2-byte profile + 2-byte tag)
	case TagControlFullyQualified8:
		skipBytes += 8 // 8-byte tag (2-byte vendor + 2-byte profile + 4-byte tag)
	}

	// Write the value portion only
	if skipBytes < len(rawTLV) {
		_, err := w.w.Write(rawTLV[skipBytes:])
		return err
	}

	return nil
}

// PutNull writes a null value with the given tag.
func (w *Writer) PutNull(tag Tag) error {
	return w.writeControlAndTag(ElementTypeNull, tag)
}

// StartStructure starts a structure container with the given tag.
func (w *Writer) StartStructure(tag Tag) error {
	if err := w.writeControlAndTag(ElementTypeStruct, tag); err != nil {
		return err
	}
	w.containerStack = append(w.containerStack, ElementTypeStruct)
	return nil
}

// StartArray starts an array container with the given tag.
func (w *Writer) StartArray(tag Tag) error {
	if err := w.writeControlAndTag(ElementTypeArray, tag); err != nil {
		return err
	}
	w.containerStack = append(w.containerStack, ElementTypeArray)
	return nil
}

// StartList starts a list container with the given tag.
func (w *Writer) StartList(tag Tag) error {
	if err := w.writeControlAndTag(ElementTypeList, tag); err != nil {
		return err
	}
	w.containerStack = append(w.containerStack, ElementTypeList)
	return nil
}

// EndContainer ends the current container.
func (w *Writer) EndContainer() error {
	if len(w.containerStack) == 0 {
		return ErrNotInContainer
	}
	w.containerStack = w.containerStack[:len(w.containerStack)-1]

	// End-of-container always has anonymous tag (tag control = 0)
	_, err := w.w.Write([]byte{byte(ElementTypeEnd)})
	return err
}

// ContainerDepth returns the current container nesting depth.
func (w *Writer) ContainerDepth() int {
	return len(w.containerStack)
}

// writeFixedValue writes a control byte, tag, and fixed-size value.
func (w *Writer) writeFixedValue(elemType ElementType, tag Tag, value []byte) error {
	if err := w.writeControlAndTag(elemType, tag); err != nil {
		return err
	}
	_, err := w.w.Write(value)
	return err
}

// writeStringValue writes a string (UTF-8 or octet) with length prefix.
func (w *Writer) writeStringValue(isUTF8 bool, tag Tag, data []byte) error {
	length := uint64(len(data))

	var elemType ElementType
	var lenBuf [8]byte
	var lenSize int

	// Choose the minimum length field size needed
	switch {
	case length <= math.MaxUint8:
		lenSize = 1
		if isUTF8 {
			elemType = ElementTypeUTF8_1
		} else {
			elemType = ElementTypeBytes1
		}
		lenBuf[0] = byte(length)
	case length <= math.MaxUint16:
		lenSize = 2
		if isUTF8 {
			elemType = ElementTypeUTF8_2
		} else {
			elemType = ElementTypeBytes2
		}
		binary.LittleEndian.PutUint16(lenBuf[:2], uint16(length))
	case length <= math.MaxUint32:
		lenSize = 4
		if isUTF8 {
			elemType = ElementTypeUTF8_4
		} else {
			elemType = ElementTypeBytes4
		}
		binary.LittleEndian.PutUint32(lenBuf[:4], uint32(length))
	default:
		lenSize = 8
		if isUTF8 {
			elemType = ElementTypeUTF8_8
		} else {
			elemType = ElementTypeBytes8
		}
		binary.LittleEndian.PutUint64(lenBuf[:8], length)
	}

	if err := w.writeControlAndTag(elemType, tag); err != nil {
		return err
	}
	if _, err := w.w.Write(lenBuf[:lenSize]); err != nil {
		return err
	}
	_, err := w.w.Write(data)
	return err
}
