package tlv

import "errors"

var (
	// ErrUnexpectedEOF is returned when the input ends unexpectedly.
	ErrUnexpectedEOF = errors.New("tlv: unexpected end of input")

	// ErrInvalidElementType is returned when an invalid element type is encountered.
	ErrInvalidElementType = errors.New("tlv: invalid element type")

	// ErrInvalidTagControl is returned when an invalid tag control is encountered.
	ErrInvalidTagControl = errors.New("tlv: invalid tag control")

	// ErrTypeMismatch is returned when trying to read a value as the wrong type.
	ErrTypeMismatch = errors.New("tlv: type mismatch")

	// ErrNotInContainer is returned when trying to exit a container when not in one.
	ErrNotInContainer = errors.New("tlv: not in container")

	// ErrUnexpectedEndOfContainer is returned when end-of-container is encountered unexpectedly.
	ErrUnexpectedEndOfContainer = errors.New("tlv: unexpected end of container")

	// ErrContainerNotClosed is returned when a container is not properly closed.
	ErrContainerNotClosed = errors.New("tlv: container not closed")

	// ErrInvalidUTF8 is returned when a UTF-8 string contains invalid sequences.
	ErrInvalidUTF8 = errors.New("tlv: invalid UTF-8 string")

	// ErrAnonymousTagInStruct is returned when an anonymous tag is used in a structure.
	ErrAnonymousTagInStruct = errors.New("tlv: anonymous tag not allowed in structure")

	// ErrTaggedElementInArray is returned when a tagged element is found in an array.
	ErrTaggedElementInArray = errors.New("tlv: tagged element not allowed in array")

	// ErrContextTagOutsideStruct is returned when a context tag is used outside a structure.
	ErrContextTagOutsideStruct = errors.New("tlv: context tag only allowed in structure")

	// ErrNoElement is returned when trying to access an element before calling Next().
	ErrNoElement = errors.New("tlv: no current element")

	// ErrValueAlreadyRead is returned when trying to read the same value twice.
	ErrValueAlreadyRead = errors.New("tlv: value already read")

	// ErrOverflow is returned when a value overflows the target type.
	ErrOverflow = errors.New("tlv: value overflow")
)
