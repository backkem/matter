package clusters

import (
	"bytes"
	"errors"

	"github.com/backkem/matter/pkg/tlv"
)

// TLV encoding/decoding errors.
var (
	ErrInvalidRequest  = errors.New("invalid command request")
	ErrInvalidResponse = errors.New("invalid command response")
	ErrMissingField    = errors.New("missing required field")
)

// CommandEncoder helps build TLV-encoded command responses.
// It wraps the response data in an anonymous structure as required
// by the Matter spec for command data fields.
type CommandEncoder struct {
	buf bytes.Buffer
	w   *tlv.Writer
}

// NewCommandEncoder creates a new command encoder.
// Call StartResponse() to begin encoding.
func NewCommandEncoder() *CommandEncoder {
	e := &CommandEncoder{}
	e.w = tlv.NewWriter(&e.buf)
	return e
}

// StartResponse begins encoding a command response structure.
// All fields should be written with context tags.
func (e *CommandEncoder) StartResponse() error {
	return e.w.StartStructure(tlv.Anonymous())
}

// Writer returns the underlying TLV writer for encoding fields.
func (e *CommandEncoder) Writer() *tlv.Writer {
	return e.w
}

// Finish completes the response and returns the encoded bytes.
func (e *CommandEncoder) Finish() ([]byte, error) {
	if err := e.w.EndContainer(); err != nil {
		return nil, err
	}
	return e.buf.Bytes(), nil
}

// Reset clears the encoder for reuse.
func (e *CommandEncoder) Reset() {
	e.buf.Reset()
	e.w = tlv.NewWriter(&e.buf)
}

// CommandDecoder helps parse TLV-encoded command requests.
type CommandDecoder struct {
	r *tlv.Reader
}

// NewCommandDecoder creates a new command decoder from raw bytes.
func NewCommandDecoder(data []byte) *CommandDecoder {
	return &CommandDecoder{
		r: tlv.NewReader(bytes.NewReader(data)),
	}
}

// Reader returns the underlying TLV reader.
func (d *CommandDecoder) Reader() *tlv.Reader {
	return d.r
}

// TLVUnmarshaler is implemented by types that can unmarshal from TLV.
// Command request structs should implement this interface.
type TLVUnmarshaler interface {
	UnmarshalTLV(r *tlv.Reader) error
}

// TLVMarshaler is implemented by types that can marshal to TLV.
// Command response structs should implement this interface.
// Re-exported from pkg/im for convenience.
type TLVMarshaler interface {
	MarshalTLV(w *tlv.Writer) error
}

// EncodeResponse encodes a command response that implements TLVMarshaler.
// The response is wrapped in an anonymous structure.
func EncodeResponse(resp TLVMarshaler) ([]byte, error) {
	if resp == nil {
		return nil, nil
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := resp.MarshalTLV(w); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeRequest decodes a command request into a TLVUnmarshaler.
func DecodeRequest(data []byte, req TLVUnmarshaler) error {
	if len(data) == 0 {
		return nil // Empty request is valid for commands with no fields
	}

	r := tlv.NewReader(bytes.NewReader(data))
	return req.UnmarshalTLV(r)
}

// EmptyResponse returns nil, indicating a command with no response data.
// Use this for commands that only return a status.
func EmptyResponse() []byte {
	return nil
}
