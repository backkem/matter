package tlv

import (
	"encoding/binary"
	"io"
	"math"
	"unicode/utf8"
)

// Reader decodes TLV elements from an io.Reader.
type Reader struct {
	r              io.Reader
	containerStack []ElementType // Track container nesting

	// Current element state
	hasElement bool
	elemType   ElementType
	tag        Tag
	valueRead  bool // Whether the value has been consumed

	// Buffered value for the current element (only for fixed-size types)
	valueBuf [8]byte
	valueLen int

	// For string types, we store the length but read lazily
	stringLen uint64
}

// NewReader creates a new TLV Reader that reads from r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r}
}

// Next advances to the next TLV element.
// Returns io.EOF when there are no more elements.
func (r *Reader) Next() error {
	// If we haven't consumed the previous value, skip it
	if r.hasElement && !r.valueRead {
		if err := r.skipValue(); err != nil {
			return err
		}
	}

	// Read control octet
	var ctrl [1]byte
	if _, err := io.ReadFull(r.r, ctrl[:]); err != nil {
		return err
	}

	var tagCtrl TagControl
	r.elemType, tagCtrl = ParseControlOctet(ctrl[0])

	// Validate element type
	if r.elemType > ElementTypeEnd {
		return ErrInvalidElementType
	}

	// Read tag
	tag, err := ReadTag(r.r, tagCtrl)
	if err != nil {
		return err
	}
	r.tag = tag

	// Read value (or length for strings)
	if err := r.readValueOrLength(); err != nil {
		return err
	}

	r.hasElement = true
	r.valueRead = false

	return nil
}

// readValueOrLength reads the value for fixed-size types or the length for strings.
func (r *Reader) readValueOrLength() error {
	switch {
	case r.elemType.IsInt() || r.elemType.IsFloat():
		// Fixed-size value
		r.valueLen = r.elemType.ValueSize()
		if r.valueLen > 0 {
			if _, err := io.ReadFull(r.r, r.valueBuf[:r.valueLen]); err != nil {
				return err
			}
		}

	case r.elemType.IsString():
		// Read length field
		lenSize := r.elemType.LengthFieldSize()
		var lenBuf [8]byte
		if _, err := io.ReadFull(r.r, lenBuf[:lenSize]); err != nil {
			return err
		}

		switch lenSize {
		case 1:
			r.stringLen = uint64(lenBuf[0])
		case 2:
			r.stringLen = uint64(binary.LittleEndian.Uint16(lenBuf[:2]))
		case 4:
			r.stringLen = uint64(binary.LittleEndian.Uint32(lenBuf[:4]))
		case 8:
			r.stringLen = binary.LittleEndian.Uint64(lenBuf[:8])
		}

	default:
		// Boolean, Null, Container start/end: no value to read
		r.valueLen = 0
		r.stringLen = 0
	}

	return nil
}

// Type returns the type of the current element.
func (r *Reader) Type() ElementType {
	return r.elemType
}

// Tag returns the tag of the current element.
func (r *Reader) Tag() Tag {
	return r.tag
}

// HasElement returns true if there is a current element.
func (r *Reader) HasElement() bool {
	return r.hasElement
}

// Int returns the current element as a signed integer.
func (r *Reader) Int() (int64, error) {
	if !r.hasElement {
		return 0, ErrNoElement
	}
	if r.valueRead {
		return 0, ErrValueAlreadyRead
	}
	if !r.elemType.IsSignedInt() {
		return 0, ErrTypeMismatch
	}

	r.valueRead = true

	switch r.elemType {
	case ElementTypeInt8:
		return int64(int8(r.valueBuf[0])), nil
	case ElementTypeInt16:
		return int64(int16(binary.LittleEndian.Uint16(r.valueBuf[:2]))), nil
	case ElementTypeInt32:
		return int64(int32(binary.LittleEndian.Uint32(r.valueBuf[:4]))), nil
	case ElementTypeInt64:
		return int64(binary.LittleEndian.Uint64(r.valueBuf[:8])), nil
	}
	return 0, ErrTypeMismatch
}

// Uint returns the current element as an unsigned integer.
func (r *Reader) Uint() (uint64, error) {
	if !r.hasElement {
		return 0, ErrNoElement
	}
	if r.valueRead {
		return 0, ErrValueAlreadyRead
	}
	if !r.elemType.IsUnsignedInt() {
		return 0, ErrTypeMismatch
	}

	r.valueRead = true

	switch r.elemType {
	case ElementTypeUInt8:
		return uint64(r.valueBuf[0]), nil
	case ElementTypeUInt16:
		return uint64(binary.LittleEndian.Uint16(r.valueBuf[:2])), nil
	case ElementTypeUInt32:
		return uint64(binary.LittleEndian.Uint32(r.valueBuf[:4])), nil
	case ElementTypeUInt64:
		return binary.LittleEndian.Uint64(r.valueBuf[:8]), nil
	}
	return 0, ErrTypeMismatch
}

// Bool returns the current element as a boolean.
func (r *Reader) Bool() (bool, error) {
	if !r.hasElement {
		return false, ErrNoElement
	}
	if r.valueRead {
		return false, ErrValueAlreadyRead
	}
	if !r.elemType.IsBool() {
		return false, ErrTypeMismatch
	}

	r.valueRead = true
	return r.elemType == ElementTypeTrue, nil
}

// Float32 returns the current element as a 32-bit float.
func (r *Reader) Float32() (float32, error) {
	if !r.hasElement {
		return 0, ErrNoElement
	}
	if r.valueRead {
		return 0, ErrValueAlreadyRead
	}
	if r.elemType != ElementTypeFloat32 {
		return 0, ErrTypeMismatch
	}

	r.valueRead = true
	bits := binary.LittleEndian.Uint32(r.valueBuf[:4])
	return math.Float32frombits(bits), nil
}

// Float64 returns the current element as a 64-bit float.
func (r *Reader) Float64() (float64, error) {
	if !r.hasElement {
		return 0, ErrNoElement
	}
	if r.valueRead {
		return 0, ErrValueAlreadyRead
	}
	if r.elemType != ElementTypeFloat64 {
		return 0, ErrTypeMismatch
	}

	r.valueRead = true
	bits := binary.LittleEndian.Uint64(r.valueBuf[:8])
	return math.Float64frombits(bits), nil
}

// String returns the current element as a UTF-8 string.
func (r *Reader) String() (string, error) {
	if !r.hasElement {
		return "", ErrNoElement
	}
	if r.valueRead {
		return "", ErrValueAlreadyRead
	}
	if !r.elemType.IsUTF8String() {
		return "", ErrTypeMismatch
	}

	r.valueRead = true

	if r.stringLen == 0 {
		return "", nil
	}

	data := make([]byte, r.stringLen)
	if _, err := io.ReadFull(r.r, data); err != nil {
		return "", err
	}

	if !utf8.Valid(data) {
		return "", ErrInvalidUTF8
	}

	return string(data), nil
}

// Bytes returns the current element as a byte slice.
func (r *Reader) Bytes() ([]byte, error) {
	if !r.hasElement {
		return nil, ErrNoElement
	}
	if r.valueRead {
		return nil, ErrValueAlreadyRead
	}
	if !r.elemType.IsBytes() {
		return nil, ErrTypeMismatch
	}

	r.valueRead = true

	if r.stringLen == 0 {
		return nil, nil
	}

	data := make([]byte, r.stringLen)
	if _, err := io.ReadFull(r.r, data); err != nil {
		return nil, err
	}

	return data, nil
}

// Null verifies the current element is a null value.
func (r *Reader) Null() error {
	if !r.hasElement {
		return ErrNoElement
	}
	if r.valueRead {
		return ErrValueAlreadyRead
	}
	if r.elemType != ElementTypeNull {
		return ErrTypeMismatch
	}

	r.valueRead = true
	return nil
}

// EnterContainer enters the current container element.
// The current element must be a structure, array, or list.
func (r *Reader) EnterContainer() error {
	if !r.hasElement {
		return ErrNoElement
	}
	if !r.elemType.IsContainer() {
		return ErrTypeMismatch
	}

	r.containerStack = append(r.containerStack, r.elemType)
	r.hasElement = false
	r.valueRead = true
	return nil
}

// ExitContainer exits the current container.
// This reads and discards any remaining elements until EndOfContainer.
func (r *Reader) ExitContainer() error {
	if len(r.containerStack) == 0 {
		return ErrNotInContainer
	}

	// If we're already positioned on the EndOfContainer marker for this container,
	// just pop the stack and return.
	if r.hasElement && r.elemType == ElementTypeEnd {
		r.containerStack = r.containerStack[:len(r.containerStack)-1]
		r.hasElement = false
		return nil
	}

	// Skip remaining elements until end-of-container
	depth := 1
	for depth > 0 {
		if err := r.Next(); err != nil {
			return err
		}

		if r.elemType == ElementTypeEnd {
			depth--
		} else if r.elemType.IsContainer() {
			depth++
		}
	}

	r.containerStack = r.containerStack[:len(r.containerStack)-1]
	r.hasElement = false
	return nil
}

// ContainerDepth returns the current container nesting depth.
func (r *Reader) ContainerDepth() int {
	return len(r.containerStack)
}

// IsEndOfContainer returns true if the current element is an end-of-container marker.
func (r *Reader) IsEndOfContainer() bool {
	return r.hasElement && r.elemType == ElementTypeEnd
}

// Skip skips the current element, including all nested elements if it's a container.
func (r *Reader) Skip() error {
	if !r.hasElement {
		return ErrNoElement
	}

	if r.elemType.IsContainer() {
		// Enter and exit to skip all nested content
		if err := r.EnterContainer(); err != nil {
			return err
		}
		return r.ExitContainer()
	}

	// For non-containers, just mark as read (value was already buffered or will be skipped)
	return r.skipValue()
}

// skipValue skips the value of the current element if not yet read.
func (r *Reader) skipValue() error {
	if r.valueRead {
		return nil
	}

	r.valueRead = true

	// For string types, we need to skip the actual string data
	if r.elemType.IsString() && r.stringLen > 0 {
		// Use io.CopyN to skip bytes efficiently
		_, err := io.CopyN(io.Discard, r.r, int64(r.stringLen))
		return err
	}

	return nil
}


// RawBytes reads the current element as raw TLV bytes.
// This includes the control byte, tag, and value bytes.
// The returned bytes can be passed to PutRaw to write the same element with a different tag.
func (r *Reader) RawBytes() ([]byte, error) {
	if !r.hasElement {
		return nil, ErrNoElement
	}

	var result []byte

	// Start with control byte and tag of current element
	ctrl := BuildControlOctet(r.elemType, r.tag.Control())
	result = append(result, ctrl)

	// Append tag bytes
	tagBytes, err := encodeTag(r.tag)
	if err != nil {
		return nil, err
	}
	result = append(result, tagBytes...)

	// Now append the value portion
	if r.elemType.IsContainer() {
		// For containers, we need to read all nested content
		if err := r.EnterContainer(); err != nil {
			return nil, err
		}

		for {
			if err := r.Next(); err != nil {
				if err == io.EOF {
					break
				}
				return nil, err
			}

			if r.IsEndOfContainer() {
				break
			}

			// Recursively read nested element (including its control and tag)
			nestedBytes, err := r.RawBytes()
			if err != nil {
				return nil, err
			}
			result = append(result, nestedBytes...)
		}

		if err := r.ExitContainer(); err != nil {
			return nil, err
		}

		// Append end-of-container marker
		result = append(result, byte(ElementTypeEnd))

	} else if r.elemType.IsString() {
		// For strings, append length encoding + string data
		lengthBytes := encodeLengthField(r.stringLen, r.elemType.LengthFieldSize())
		result = append(result, lengthBytes...)

		if r.stringLen > 0 {
			stringData := make([]byte, r.stringLen)
			if _, err := io.ReadFull(r.r, stringData); err != nil {
				return nil, err
			}
			result = append(result, stringData...)
		}
		r.valueRead = true

	} else {
		// For fixed-size types, append the buffered value
		result = append(result, r.valueBuf[:r.valueLen]...)
		r.valueRead = true
	}

	return result, nil
}

// encodeTag encodes a tag to bytes.
func encodeTag(tag Tag) ([]byte, error) {
	switch tag.Control() {
	case TagControlAnonymous:
		return nil, nil
	case TagControlContext:
		return []byte{byte(tag.TagNumber())}, nil
	case TagControlCommonProfile2:
		return []byte{byte(tag.TagNumber()), byte(tag.TagNumber() >> 8)}, nil
	case TagControlCommonProfile4:
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, tag.TagNumber())
		return b, nil
	case TagControlImplicitProfile2:
		return []byte{byte(tag.TagNumber()), byte(tag.TagNumber() >> 8)}, nil
	case TagControlImplicitProfile4:
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, tag.TagNumber())
		return b, nil
	case TagControlFullyQualified6:
		b := make([]byte, 6)
		binary.LittleEndian.PutUint16(b[0:], uint16(tag.VendorID()))
		binary.LittleEndian.PutUint16(b[2:], uint16(tag.ProfileNumber()))
		binary.LittleEndian.PutUint16(b[4:], uint16(tag.TagNumber()))
		return b, nil
	case TagControlFullyQualified8:
		b := make([]byte, 8)
		binary.LittleEndian.PutUint16(b[0:], uint16(tag.VendorID()))
		binary.LittleEndian.PutUint16(b[2:], uint16(tag.ProfileNumber()))
		binary.LittleEndian.PutUint32(b[4:], tag.TagNumber())
		return b, nil
	default:
		return nil, ErrInvalidTagControl
	}
}

// encodeLengthField encodes a length value according to the field size.
func encodeLengthField(length uint64, fieldSize int) []byte {
	b := make([]byte, fieldSize)
	switch fieldSize {
	case 1:
		b[0] = byte(length)
	case 2:
		binary.LittleEndian.PutUint16(b, uint16(length))
	case 4:
		binary.LittleEndian.PutUint32(b, uint32(length))
	case 8:
		binary.LittleEndian.PutUint64(b, length)
	}
	return b
}
