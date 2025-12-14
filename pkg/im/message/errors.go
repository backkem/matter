package message

import "errors"

// Encoding/decoding errors.
var (
	ErrInvalidType     = errors.New("im: invalid TLV type")
	ErrMissingField    = errors.New("im: missing required field")
	ErrUnexpectedEnd   = errors.New("im: unexpected end of data")
	ErrInvalidTag      = errors.New("im: invalid tag")
	ErrMalformedPath   = errors.New("im: malformed path")
	ErrInvalidStatus   = errors.New("im: invalid status")
)
